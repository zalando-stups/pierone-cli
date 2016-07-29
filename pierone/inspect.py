import io
import struct
import tarfile
import tempfile
import zlib

from .api import request

FTEXT, FHCRC, FEXTRA, FNAME, FCOMMENT = 1, 2, 4, 8, 16

CHUNK_SIZE = 16384


def _read_gzip_header(fp):
    magic = fp.read(2)
    if magic == b'':
        return False

    if magic != b'\037\213':
        raise OSError('Not a gzipped file (%r)' % magic)

    (method, flag,
        _last_mtime) = struct.unpack("<BBIxx", fp.read(8))
    if method != 8:
        raise OSError('Unknown compression method')

    if flag & FEXTRA:
        # Read & discard the extra field, if present
        extra_len, = struct.unpack("<H", fp.read(2))
        fp.read(extra_len)
    if flag & FNAME:
        # Read and discard a null-terminated string containing the filename
        while True:
            s = fp.read(1)
            if not s or s == b'\000':
                break
    if flag & FCOMMENT:
        # Read and discard a null-terminated string containing a comment
        while True:
            s = fp.read(1)
            if not s or s == b'\000':
                break
    if flag & FHCRC:
        fp.read(2)     # Read & discard the 16-bit header CRC
    return True


class Gzip():
    def __init__(self, fd):
        _read_gzip_header(fd)
        self._decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
        self._fp = fd
        self._pos = 0
        self._unconsumed = b''

    def read(self, size):
        buf = self._unconsumed + self._fp.read(io.DEFAULT_BUFFER_SIZE)
        self._unconsumed = b''
        uncompress = self._decompressor.decompress(buf, size)
        self._unconsumed = self._decompressor.unconsumed_tail
        self._pos += len(uncompress)
        return uncompress

    def tell(self):
        return self._pos

    def seek(self, offset):
        return offset
        pass


def inspect_files(url, team, artifact, tag, token, callback):
    response = request(url, '/v2/{}/{}/manifests/{}'.format(team, artifact, tag),
                       token)
    if not response.ok:
        return
    row = response.json()
    if row.get('layers'):
        layers = reversed([lay.get('digest') for lay in row.get('layers')])
    else:
        layers = [lay.get('blobSum') for lay in row.get('fsLayers')]
    seen_members = set()
    for i, layer in enumerate(layers):
        layer_id = layer
        if layer_id:
            response = request(url, '/v2/{}/{}/blobs/{}'.format(team, artifact, layer_id), token,
                               stream=True)
            with tempfile.NamedTemporaryFile(prefix='tmp-layer-', suffix='.tar') as fd:
                for chunk in response.iter_content(CHUNK_SIZE):
                    fd.seek(0, 2)
                    fd.write(chunk)
                    fd.flush()
                    fd.seek(0)
                    with tarfile.TarFile(fileobj=Gzip(fd), mode='r') as archive:
                        for member in archive.getmembers():
                            key = (layer_id, member.name, member.type)
                            if key not in seen_members:
                                abort = callback(i, layer_id, member)
                                if abort:
                                    return
                                seen_members.add(key)


def get_config(url, team, artifact, tag, token):
    row = request(url, '/v2/{}/{}/manifests/{}'.format(team, artifact, tag),
                  token).json()

    if row.get('config'):
        config_id = row['config']['digest']
        response = request(url, '/v2/{}/{}/blobs/{}'.format(team, artifact, config_id), token)
        return response.json()
