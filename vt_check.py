"""
vt_check.py - a pyhiew script to display virustotal analysis results for open file

This plugin based on code by Bryce Boe: http://www.bryceboe.com/2010/09/01/submitting-binaries-to-virustotal/
Some functions use modified code from the snippet at: http://code.activestate.com/recipes/146306/

"""
import hiew
import hashlib, httplib, mimetypes, os, pprint, simplejson, sys, urlparse

# -----------------------------------------------------------------------
DEFAULT_TYPE = 'application/octet-stream'
FILE_REPORT_URL = 'https://www.virustotal.com/api/get_file_report.json'
SCAN_URL = 'https://www.virustotal.com/api/scan_file.json'
API_KEY = "KEY"

def _encode_multipart_formdata(fields, files=()):
    BOUNDARY = '----------ThIs_Is_tHe_bouNdaRY_$'
    CRLF = '\r\n'
    L = []
    for key, value in fields.items():
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"' % key)
        L.append('')
        L.append(value)
    for (key, filename, value) in files:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"; filename="%s"' %
                 (key, filename))
        content_type = mimetypes.guess_type(filename)[0] or DEFAULT_TYPE
        L.append('Content-Type: %s' % content_type)
        L.append('')
        L.append(value)
    L.append('--' + BOUNDARY + '--')
    L.append('')
    body = CRLF.join(L)
    content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
    return content_type, body

def _post_multipart(url, fields, files=()):
    content_type, data = _encode_multipart_formdata(fields, files)
    url_parts = urlparse.urlparse(url)
    if url_parts.scheme == 'http':
        h = httplib.HTTPConnection(url_parts.netloc)
    elif url_parts.scheme == 'https':
        h = httplib.HTTPSConnection(url_parts.netloc)
    else:
        raise Exception('Unsupported URL scheme')
    path = urlparse.urlunparse(('', '') + url_parts[2:])
    h.request('POST', path, data, {'content-type':content_type})
    return h.getresponse().read()

def scan_file(filename):
    """
    Uploads a file for scanning.

    @param filename: The filename to upload

    @return: - None if upload failed
             - scan_id value if upload succeeds
             - raises an exception on IO failures
    """
    files = [('file', filename, open(filename, 'rb').read())]
    json = _post_multipart(SCAN_URL, {'key':API_KEY}, files)
    data = simplejson.loads(json)
    return str(data['scan_id']) if data['result'] == 1 else None

def get_file_md5_hash(filename):
    f = open(filename, 'rb')
    r = hashlib.md5(f.read()).hexdigest()
    f.close()
    return r

def get_file_report(filename=None, md5sum=None):
    """
    Returns an report for a file or md5su.

    @param filename: File name to get report. The file is used just
                     to compute its MD5Sum
    @param md5sum: MD5sum string (in case filename was not passed)

    @return: - None: if file was not previously analyzed
             - A dictionary if report exists: key=scanner, value=reported name
    """
    if filename is None and md5sum is None:
        raise Exception('Either filename or md5sum should be passed!')

    if filename:
        global LAST_FILE_HASH
        LAST_FILE_HASH = md5sum = get_file_md5_hash(filename)

    json = _post_multipart(FILE_REPORT_URL, {'resource':md5sum, 'key':API_KEY})
    data = simplejson.loads(json)
    if data['result'] != 1:
        return None
    else:
        return data['report'][1]

# -----------------------------------------------------------------------
file = hiew.Data.GetFileName()
md5 = get_file_md5_hash(file)

def parse_result(result={}):
    av_num = 0
    dt_num = 0
    for av, mwname in result.items():
      av_num = av_num + 1
      if mwname:
        dt_num = dt_num + 1

    items = ["", "File Name: %s" % file, "Detection Rate: %s/%s" % (av_num, dt_num), ""]
    for av, mwname in result.items():
        mwname = str(mwname)
        av = str(av)
        av_num = av_num + 1
        if mwname:
          dt_num = dt_num + 1
          items.append(str(av + " - " + mwname))
    return items

def vt_report(file, md5):
    result = get_file_report(filename=file, md5sum=md5)

    if result is None:
        result = scan_file(file)
        hiew.Message(title=" VT Error ", msg="Don't find results")
    else:
        return parse_result(result)

def VtMain():
    hiew.MessageWaitOpen(msg = "Processing VT check");
    lines = vt_report(file, md5)
    w = hiew.Window()
    w.Create(
       title = " -=VT Check Results=- ",
       lines = lines,
        width = 70,
        main_keys = "")
    w.Show()

# -----------------------------------------------------------------------
VtMain()