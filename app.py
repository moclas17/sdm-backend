# pylint: disable=unused-import

import argparse
import binascii

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import BadRequest

from config import (
    CTR_PARAM,
    REQUIRE_LRP,
    SDMMAC_PARAM,
    MASTER_KEY,
    UID_PARAM,
    DERIVE_MODE,
)

if DERIVE_MODE == "legacy":
    from libsdm.legacy_derive import derive_tag_key
elif DERIVE_MODE == "standard":
    from libsdm.derive import derive_tag_key
else:
    raise RuntimeError("Invalid DERIVE_MODE.")

from libsdm.sdm import (
    EncMode,
    InvalidMessage,
    validate_plain_sun,
)

app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True


@app.errorhandler(400)
def handler_bad_request(err):
    return render_template('error.html', code=400, msg=str(err)), 400


@app.errorhandler(403)
def handler_forbidden(err):
    return render_template('error.html', code=403, msg=str(err)), 403


@app.errorhandler(404)
def handler_not_found(err):
    return render_template('error.html', code=404, msg=str(err)), 404




@app.route('/')
def sdm_main():
    """
    Main page with validation functionality.
    """
    # Check if parameters are provided for validation
    if request.args.get(UID_PARAM) and request.args.get(CTR_PARAM) and request.args.get(SDMMAC_PARAM):
        try:
            uid = binascii.unhexlify(request.args[UID_PARAM])
            read_ctr = binascii.unhexlify(request.args[CTR_PARAM])
            cmac = binascii.unhexlify(request.args[SDMMAC_PARAM])
        except binascii.Error:
            return jsonify({
                "valid": False,
                "error": "Failed to decode parameters."
            })

        try:
            sdm_file_read_key = derive_tag_key(MASTER_KEY, uid, 2)
            res = validate_plain_sun(uid=uid,
                                     read_ctr=read_ctr,
                                     sdmmac=cmac,
                                     sdm_file_read_key=sdm_file_read_key)
        except InvalidMessage:
            return jsonify({
                "valid": False,
                "error": "Invalid message (most probably wrong signature)."
            })

        if REQUIRE_LRP and res['encryption_mode'] != EncMode.LRP:
            return jsonify({
                "valid": False,
                "error": "Invalid encryption mode, expected LRP."
            })

        return jsonify({
            "valid": True,
            "message": "Cryptographic signature validated",
            "uid": res['uid'].hex().upper(),
            "read_ctr": res['read_ctr'],
            "enc_mode": res['encryption_mode'].name
        })

    # If no parameters, show main page
    return render_template('sdm_main.html')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='OTA NFC Server')
    parser.add_argument('--host', type=str, nargs='?', help='address to listen on')
    parser.add_argument('--port', type=int, nargs='?', help='port to listen on')

    args = parser.parse_args()

    app.run(host=args.host, port=args.port)
