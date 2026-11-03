"""
AGOL -> Google Drive photo-attachment pipeline  (Flour_Survey)
---------------------------------------------------------------
For every survey feature that HAS photo attachments and NO Drive link yet:
  1. Create (or reuse) a Drive folder named  "<Block_No>_<Shop_Code>"
  2. Upload its photos into that folder (skipping duplicates by content hash)
  3. Write the folder's shareable link back to the "Drive_Link" field on AGOL

Guarantees the requested behaviour:
  (1) photo -> folder "BlockCode_ID" -> link written back to feature layer
  (2) folder already exists  -> reused, never duplicated   (search-before-create)
  (3) duplicate photos       -> detected by MD5 and removed / not re-uploaded
  (4) username / password     -> validated, fails loudly with a clear error
  (5) feature layer           -> validated (reachable + hasAttachments + fields)
  (6) fully automatic         -> runs on Cloud Run, triggered by Cloud Scheduler

Runs as a Service Account via ADC on Cloud Run (no OAuth key files).
"""

import os
import io
import hmac
import hashlib
import re
import logging

import requests
from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse

from google.oauth2.credentials import Credentials as UserCredentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload

# ----------------------------------------------------------------------------
# Configuration (all from environment / Secret Manager)
# ----------------------------------------------------------------------------
ARCGIS_USERNAME   = os.environ.get("ARCGIS_USERNAME", "")
ARCGIS_PASSWORD   = os.environ.get("ARCGIS_PASSWORD", "")
TOKEN_URL         = os.environ.get(
    "ARCGIS_TOKEN_URL",
    "https://adhocportal.maps.arcgis.com/sharing/rest/generateToken",
)
# .../FeatureServer   (layer index appended below)
SERVICE_URL       = os.environ.get("FEATURE_SERVICE_URL", "").rstrip("/")
LAYER_INDEX       = os.environ.get("LAYER_INDEX", "0")
LAYER_URL         = f"{SERVICE_URL}/{LAYER_INDEX}"

DRIVE_ROOT_FOLDER_ID = os.environ["DRIVE_ROOT_FOLDER_ID"]
WEBHOOK_SECRET       = os.environ.get("WEBHOOK_SECRET", "")

# Field names on the hosted layer
F_BLOCK   = os.environ.get("FIELD_BLOCK", "Block_No")
F_SHOP    = os.environ.get("FIELD_SHOP",  "Shop_Code")
F_LINK    = os.environ.get("FIELD_LINK",  "Drive_Link")
OID_FIELD = os.environ.get("FIELD_OID",   "OBJECTID")

DRIVE_SCOPES = ["https://www.googleapis.com/auth/drive.file"]

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(message)s")
log = logging.getLogger("agol2drive")

app = FastAPI()
http = requests.Session()


# ----------------------------------------------------------------------------
# (4) ArcGIS auth — validated, fails loudly
# ----------------------------------------------------------------------------
def arcgis_token() -> str:
    if not ARCGIS_USERNAME or not ARCGIS_PASSWORD:
        raise RuntimeError("ARCGIS_USERNAME / ARCGIS_PASSWORD not set")
    r = http.post(
        TOKEN_URL,
        data={
            "username": ARCGIS_USERNAME,
            "password": ARCGIS_PASSWORD,
            "referer":  "https://www.arcgis.com",
            "f":        "json",
            "expiration": 60,
        },
        timeout=30,
    )
    j = r.json()
    if "token" not in j:
        # e.g. {'error': {'code': 400, 'message': 'Unable to generate token',
        #                 'details': ['Invalid username or password.']}}
        raise RuntimeError(f"ArcGIS login failed: {j.get('error', j)}")
    return j["token"]


def agol(path: str, token: str, **params):
    """POST to an AGOL REST endpoint and return parsed JSON."""
    params.update(f="json", token=token)
    r = http.post(f"{LAYER_URL}/{path}" if path else f"{LAYER_URL}",
                  data=params, timeout=90)
    r.raise_for_status()
    return r.json()


# ----------------------------------------------------------------------------
# (5) Feature-layer validation
# ----------------------------------------------------------------------------
def verify_layer(token: str) -> dict:
    if not SERVICE_URL:
        raise RuntimeError("FEATURE_SERVICE_URL not set")
    r = http.get(LAYER_URL, params={"f": "json", "token": token}, timeout=60)
    r.raise_for_status()
    meta = r.json()
    if "error" in meta:
        raise RuntimeError(f"Feature layer unreachable: {meta['error']}")
    if not meta.get("hasAttachments"):
        raise RuntimeError("Feature layer has NO attachments enabled")
    names = {f["name"] for f in meta.get("fields", [])}
    missing = [f for f in (F_BLOCK, F_SHOP, F_LINK) if f not in names]
    if missing:
        raise RuntimeError(f"Feature layer missing fields: {missing}")
    return meta


# ----------------------------------------------------------------------------
# Google Drive (Service Account via ADC)
# ----------------------------------------------------------------------------
def drive():
    creds = UserCredentials(
        None,
        refresh_token=os.environ["GOOGLE_REFRESH_TOKEN"],
        client_id=os.environ["GOOGLE_CLIENT_ID"],
        client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
        token_uri="https://oauth2.googleapis.com/token",
        scopes=DRIVE_SCOPES,
    )
    return build("drive", "v3", credentials=creds, cache_discovery=False)


def _q_escape(name: str) -> str:
    return name.replace("\\", "\\\\").replace("'", "\\'")


def get_or_create_folder(svc, name: str) -> str:
    """
    (2) Search first. If one or more folders with this name already exist under
    the root, REUSE the oldest and trash any extras (self-healing against the
    old duplicate-folder bug). Only create a brand-new folder when none exists.
    """
    q = (
        f"name = '{_q_escape(name)}' and "
        f"'{DRIVE_ROOT_FOLDER_ID}' in parents and "
        f"mimeType = 'application/vnd.google-apps.folder' and trashed = false"
    )
    res = svc.files().list(
        q=q, fields="files(id,createdTime)",
        orderBy="createdTime", pageSize=100,
        supportsAllDrives=True, includeItemsFromAllDrives=True,
    ).execute()
    folders = res.get("files", [])

    if folders:
        keep = folders[0]["id"]
        for extra in folders[1:]:                       # trash duplicates
            try:
                svc.files().update(fileId=extra["id"],
                                   body={"trashed": True},
                                   supportsAllDrives=True).execute()
                log.info("  trashed duplicate folder %s (%s)", extra["id"], name)
            except Exception as e:
                log.warning("  could not trash dup folder %s: %s", extra["id"], e)
        return keep

    meta = {
        "name": name,
        "mimeType": "application/vnd.google-apps.folder",
        "parents": [DRIVE_ROOT_FOLDER_ID],
    }
    folder = svc.files().create(body=meta, fields="id",
                                supportsAllDrives=True).execute()
    log.info("  created folder %s (%s)", folder["id"], name)
    return folder["id"]


def folder_files(svc, folder_id: str) -> dict:
    """Return {md5: fileId} for existing files, trashing in-folder duplicates (3)."""
    seen, dupes = {}, []
    page = None
    while True:
        res = svc.files().list(
            q=f"'{folder_id}' in parents and trashed = false",
            fields="nextPageToken, files(id,name,md5Checksum)",
            pageSize=200, pageToken=page,
            supportsAllDrives=True, includeItemsFromAllDrives=True,
        ).execute()
        for f in res.get("files", []):
            h = f.get("md5Checksum")
            if not h:
                continue
            if h in seen:
                dupes.append(f["id"])                   # duplicate content
            else:
                seen[h] = f["id"]
        page = res.get("nextPageToken")
        if not page:
            break
    for fid in dupes:                                   # (3) remove duplicates
        try:
            svc.files().update(fileId=fid, body={"trashed": True},
                               supportsAllDrives=True).execute()
            log.info("  trashed duplicate photo %s", fid)
        except Exception as e:
            log.warning("  could not trash dup photo %s: %s", fid, e)
    return seen


def link_for(folder_id: str) -> str:
    return f"https://drive.google.com/drive/folders/{folder_id}"


# ----------------------------------------------------------------------------
# Per-feature processing
# ----------------------------------------------------------------------------
def safe(val, fallback) -> str:
    s = "" if val is None else str(val).strip()
    s = re.sub(r"[\\/:*?\"<>|]+", "-", s)               # Drive-unsafe chars
    return s or str(fallback)


def process_feature(svc, token: str, oid: int, attrs: dict) -> dict:
    # attachment list
    att = agol(f"{oid}/attachments", token).get("attachmentInfos", [])
    photos = [a for a in att if str(a.get("contentType", "")).startswith("image")]
    if not photos:
        return {"oid": oid, "skipped": "no photos"}

    name = f"{safe(attrs.get(F_BLOCK), 'NA')}_{safe(attrs.get(F_SHOP), oid)}"
    g_ok = False
    folder_id = None
    existing = {}
    try:
        folder_id = get_or_create_folder(svc, name)
        existing = folder_files(svc, folder_id)
        g_ok = True
    except Exception as e:
        log.warning("  gdrive setup failed oid %s: %s", oid, e)

    od_at = od_fid = od_url = None
    od_names = set()
    if ENABLE_ONEDRIVE:
        try:
            od_at = ms_token()
            od_fid, od_url = od_get_or_create_folder(od_at, name)
            od_url = od_share_link(od_at, od_fid) or od_url
            od_names = od_folder_names(od_at, od_fid)
        except Exception as e:
            log.warning("  onedrive setup failed oid %s: %s", oid, e)
            od_at = od_fid = None

    uploaded = od_uploaded = 0
    for a in photos:
        url = f"{LAYER_URL}/{oid}/attachments/{a['id']}"
        blob = http.get(url, params={"token": token}, timeout=120).content
        h = hashlib.md5(blob).hexdigest()
        fname = a.get("name") or f"{oid}_{a['id']}.jpg"
        if g_ok and h not in existing:
            try:
                media = MediaIoBaseUpload(io.BytesIO(blob),
                    mimetype=a.get("contentType", "image/jpeg"), resumable=False)
                svc.files().create(body={"name": fname, "parents": [folder_id]},
                    media_body=media, fields="id",
                    supportsAllDrives=True).execute(num_retries=5)
                existing[h] = True
                uploaded += 1
            except Exception as e:
                log.warning("  gdrive upload failed oid %s: %s", oid, e)
        if od_fid and fname not in od_names:
            try:
                od_upload(od_at, od_fid, fname, blob,
                          a.get("contentType", "image/jpeg"))
                od_names.add(fname)
                od_uploaded += 1
            except Exception as e:
                log.warning("  onedrive upload failed oid %s: %s", oid, e)

    link = link_for(folder_id) if g_ok else None
    if g_ok and link and (attrs.get(F_LINK) or "").strip() != link:
        _write_link(token, oid, F_LINK, link)
    if od_url and (attrs.get(F_OD_LINK) or "").strip() != od_url:
        _write_link(token, oid, F_OD_LINK, od_url)

    return {"oid": oid, "folder": name, "uploaded": uploaded,
            "od_uploaded": od_uploaded, "link": link, "od_link": od_url}


# ----------------------------------------------------------------------------
# Main sync
# ----------------------------------------------------------------------------
def run_sync(where: str, max_features: int = 25) -> dict:
    token = arcgis_token()                              # (4)
    verify_layer(token)                                 # (5)
    svc = drive()

    all_ids = agol("query", token, where=where,
                   returnIdsOnly="true").get("objectIds", []) or []
    # keep only candidates that actually have image attachments, so photo-less
    # features never clog the per-run slice
    with_photos = []
    for j in range(0, len(all_ids), 100):
        grp = agol("queryAttachments", token,
                   objectIds=",".join(map(str, all_ids[j:j + 100])))
        for g in grp.get("attachmentGroups", []):
            if any(str(a.get("contentType", "")).startswith("image")
                   for a in g.get("attachmentInfos", [])):
                with_photos.append(g["parentObjectId"])
    ids = with_photos[:max_features] if max_features else with_photos
    log.info("sync: %d empty-link, %d with photos, processing %d this run",
             len(all_ids), len(with_photos), len(ids))

    results, errors = [], []
    for i in range(0, len(ids), 200):                   # fetch attrs in batches
        batch = ids[i:i + 200]
        feats = agol(
            "query", token,
            objectIds=",".join(map(str, batch)),
            outFields=f"{OID_FIELD},{F_BLOCK},{F_SHOP},{F_LINK},{F_OD_LINK}",
            returnGeometry="false",
        ).get("features", [])
        for ft in feats:
            a = ft["attributes"]
            oid = a[OID_FIELD]
            try:
                results.append(process_feature(svc, token, oid, a))
            except Exception as e:
                log.exception("feature %s failed", oid)
                errors.append({"oid": oid, "error": str(e)})

    done = [r for r in results if r.get("uploaded") is not None]
    return {
        "ok": True,
        "candidates": len(all_ids),
        "with_photos": len(with_photos),
        "remaining": max(0, len(with_photos) - len(ids)),
        "processed": len(done),
        "uploaded_total": sum(r.get("uploaded", 0) for r in done),
        "errors": errors,
        "details": done,
    }


# ----------------------------------------------------------------------------
# HTTP endpoints
# ----------------------------------------------------------------------------
def _auth(key: str) -> bool:
    return bool(WEBHOOK_SECRET) and hmac.compare_digest(key, WEBHOOK_SECRET)


@app.get("/")
def root():
    return {"service": "agol2drive", "status": "up"}


@app.get("/health")
def health():
    """(4)+(5) credential + layer check without doing any work."""
    try:
        token = arcgis_token()
        meta = verify_layer(token)
        return {"ok": True, "arcgis_login": "ok",
                "layer": meta.get("name"),
                "hasAttachments": meta.get("hasAttachments")}
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})


@app.get("/sync")
def sync(key: str = Query(default=""),
         all: int = Query(default=0),
         limit: int = Query(default=25)):
    """
    (6) Called automatically by Cloud Scheduler every 10 min.
    Default: only features WITH attachments and an EMPTY Drive_Link.
    ?all=1 : re-check every feature (idempotent; reuses folders, dedups photos).
    """
    if not _auth(key):
        return JSONResponse(status_code=401, content={"error": "key required"})
    where = "1=1" if all else f"({F_LINK} IS NULL OR {F_LINK} = '') OR ({F_OD_LINK} IS NULL OR {F_OD_LINK} = '')"
    try:
        return run_sync(where, limit)
    except Exception as e:
        log.exception("sync failed")
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})


import re as _re_repair
import time as _time_repair

@app.get("/repair")
def repair(key: str = Query(default=""), budget: int = Query(default=850)):
    """Re-upload photos into empty linked folders. Time-bounded; run repeatedly."""
    if not _auth(key):
        return JSONResponse(status_code=401, content={"error": "key required"})
    t0 = _time_repair.time()
    token = arcgis_token(); verify_layer(token); svc = drive()
    feats = agol("query", token,
                 where=f"{F_LINK} IS NOT NULL AND {F_LINK} <> ''",
                 outFields=f"{OID_FIELD},{F_BLOCK},{F_SHOP},{F_LINK},{F_OD_LINK}",
                 returnGeometry="false").get("features", [])
    checked = empty = fixed = uploaded_total = no_photos = 0
    errors = []; fixed_sample = []; stopped = False
    for ft in feats:
        if _time_repair.time() - t0 > budget:
            stopped = True; break
        a = ft["attributes"]; oid = a[OID_FIELD]; link = a.get(F_LINK) or ""
        m = _re_repair.search(r"/folders/([A-Za-z0-9_-]+)", link)
        fid = m.group(1) if m else None
        checked += 1
        has = False
        if fid:
            try:
                r = svc.files().list(
                    q=f"'{fid}' in parents and trashed=false",
                    fields="files(id)", pageSize=5,
                    supportsAllDrives=True, includeItemsFromAllDrives=True).execute()
                has = len(r.get("files", [])) > 0
            except Exception:
                has = False
        if has:
            continue
        empty += 1
        try:
            res = process_feature(svc, token, oid, a)
            if res.get("uploaded") is None:
                no_photos += 1
            else:
                fixed += 1; uploaded_total += res.get("uploaded", 0)
                if len(fixed_sample) < 30:
                    fixed_sample.append({"code": f"{a.get(F_BLOCK)}_{a.get(F_SHOP)}",
                                         "uploaded": res["uploaded"]})
        except Exception as e:
            errors.append({"code": f"{a.get(F_BLOCK)}_{a.get(F_SHOP)}",
                           "error": str(e)[:140]})
    return {"ok": True, "total_linked": len(feats), "checked": checked,
            "stopped_at_budget": stopped, "empty_folders": empty,
            "fixed": fixed, "uploaded_total": uploaded_total,
            "empty_no_photos": no_photos, "errors": errors[:30],
            "fixed_sample": fixed_sample}


@app.get("/dedupe")
def dedupe(key: str = Query(default=""), budget: int = Query(default=500)):
    """Remove duplicate photos (same MD5) from each folder; fill empty ones."""
    if not _auth(key):
        return JSONResponse(status_code=401, content={"error": "key required"})
    import time as _t, re as _r
    t0 = _t.time()
    token = arcgis_token(); verify_layer(token); svc = drive()
    feats = agol("query", token,
                 where=f"{F_LINK} IS NOT NULL AND {F_LINK} <> ''",
                 outFields=f"{OID_FIELD},{F_BLOCK},{F_SHOP},{F_LINK},{F_OD_LINK}",
                 returnGeometry="false").get("features", [])
    checked = cleaned = dups_removed = filled = 0
    errors = []; stopped = False
    for ft in feats:
        if _t.time() - t0 > budget:
            stopped = True; break
        a = ft["attributes"]; oid = a[OID_FIELD]; link = a.get(F_LINK) or ""
        m = _r.search(r"/folders/([A-Za-z0-9_-]+)", link)
        fid = m.group(1) if m else None
        if not fid:
            continue
        checked += 1
        try:
            r = svc.files().list(
                q=f"'{fid}' in parents and trashed=false",
                fields="files(id,md5Checksum)", pageSize=200,
                supportsAllDrives=True, includeItemsFromAllDrives=True).execute()
            files = r.get("files", [])
        except Exception:
            files = None
        if not files:
            try:
                res = process_feature(svc, token, oid, a)
                if res.get("uploaded"):
                    filled += 1
            except Exception as e:
                errors.append({"oid": oid, "error": str(e)[:120]})
            continue
        seen = set(); removed = 0
        for f in files:
            h = f.get("md5Checksum")
            if not h:
                continue
            if h in seen:
                try:
                    svc.files().update(fileId=f["id"], body={"trashed": True},
                                       supportsAllDrives=True).execute()
                    removed += 1
                except Exception:
                    pass
            else:
                seen.add(h)
        if removed:
            cleaned += 1; dups_removed += removed
    return {"ok": True, "total": len(feats), "checked": checked,
            "stopped_at_budget": stopped, "folders_cleaned": cleaned,
            "dups_removed": dups_removed, "filled": filled, "errors": errors[:30]}



# ===== OneDrive (Microsoft Graph, delegated refresh token) =====
import time as _ms_time, json as _json_od
from urllib.parse import quote as _odq
MS_TENANT = os.environ.get("MS_TENANT_ID", "")
MS_CLIENT = os.environ.get("MS_CLIENT_ID", "")
MS_REFRESH = os.environ.get("MS_REFRESH_TOKEN", "")
ONEDRIVE_ROOT_NAME = os.environ.get("ONEDRIVE_ROOT_NAME", "ArcGIS Photos")
F_OD_LINK = os.environ.get("FIELD_OD_LINK", "OneDrive_Link")
GRAPH = "https://graph.microsoft.com/v1.0"
ENABLE_ONEDRIVE = bool(MS_TENANT and MS_CLIENT and MS_REFRESH)
_ms_tok = {"t": 0.0, "v": None}
_od_root = {}


def _write_link(token, oid, field, value):
    upd = _json_od.dumps([{"attributes": {OID_FIELD: oid, field: value}}])
    res = agol("applyEdits", token, updates=upd)
    ok = res.get("updateResults", [{}])[0].get("success", False)
    if not ok:
        log.warning("  write-back failed oid %s field %s: %s", oid, field, res)


def ms_token():
    if _ms_tok["v"] and _ms_time.time() - _ms_tok["t"] < 3000:
        return _ms_tok["v"]
    r = http.post(f"https://login.microsoftonline.com/{MS_TENANT}/oauth2/v2.0/token",
        data={"client_id": MS_CLIENT, "grant_type": "refresh_token",
              "refresh_token": MS_REFRESH,
              "scope": "offline_access Files.ReadWrite User.Read"}, timeout=30)
    j = r.json()
    if "access_token" not in j:
        raise RuntimeError(f"MS token failed: {j.get('error_description', j)}")
    _ms_tok["t"] = _ms_time.time(); _ms_tok["v"] = j["access_token"]
    return j["access_token"]


def od_get_or_create_folder(at, name):
    h = {"Authorization": f"Bearer {at}"}
    if "id" not in _od_root:
        rr = http.get(f"{GRAPH}/me/drive/root:/{_odq(ONEDRIVE_ROOT_NAME)}", headers=h, timeout=30)
        if rr.status_code == 200:
            _od_root["id"] = rr.json()["id"]
        else:
            c = http.post(f"{GRAPH}/me/drive/root/children",
                headers={**h, "Content-Type": "application/json"},
                json={"name": ONEDRIVE_ROOT_NAME, "folder": {},
                      "@microsoft.graph.conflictBehavior": "fail"}, timeout=30).json()
            _od_root["id"] = c["id"]
    root_id = _od_root["id"]
    cr = http.get(f"{GRAPH}/me/drive/items/{root_id}:/{_odq(name)}", headers=h,
                  params={"$select": "id,webUrl,folder"}, timeout=30)
    if cr.status_code == 200 and "folder" in cr.json():
        j = cr.json(); return j["id"], j.get("webUrl")
    c = http.post(f"{GRAPH}/me/drive/items/{root_id}/children",
        headers={**h, "Content-Type": "application/json"},
        json={"name": name, "folder": {},
              "@microsoft.graph.conflictBehavior": "fail"}, timeout=30).json()
    return c["id"], c.get("webUrl")


def od_folder_names(at, folder_id):
    h = {"Authorization": f"Bearer {at}"}
    names = set()
    url = f"{GRAPH}/me/drive/items/{folder_id}/children?$select=name&$top=200"
    while url:
        j = http.get(url, headers=h, timeout=30).json()
        for it in j.get("value", []):
            names.add(it.get("name"))
        url = j.get("@odata.nextLink")
    return names


def od_upload(at, folder_id, name, blob, mime):
    r = http.put(f"{GRAPH}/me/drive/items/{folder_id}:/{_odq(name)}:/content",
        headers={"Authorization": f"Bearer {at}", "Content-Type": mime},
        data=blob, timeout=180)
    r.raise_for_status()


OD_SHARE_SCOPE = os.environ.get("OD_SHARE_SCOPE", "anonymous")

def od_share_link(at, folder_id):
    h = {"Authorization": f"Bearer {at}", "Content-Type": "application/json"}
    scopes = [OD_SHARE_SCOPE] + (["organization"] if OD_SHARE_SCOPE != "organization" else [])
    for sc in scopes:
        r = http.post(f"{GRAPH}/me/drive/items/{folder_id}/createLink",
            headers=h, json={"type": "view", "scope": sc}, timeout=30)
        if r.status_code in (200, 201):
            return r.json().get("link", {}).get("webUrl")
    return None
