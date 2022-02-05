from flask import abort, request, render_template, Response
from .web import app
from . import crypto
from . import model
from . import utils
from . import config
from . import http

from werkzeug.routing import BaseConverter, ValidationError

from io import BytesIO

import qrencode

from PIL.Image import NEAREST


class RoomTokenConverter(BaseConverter):
    regex = r"[\w-]{1,64}"

    def to_python(self, value):
        try:
            return model.Room(token=value)
        except model.NoSuchRoom:
            raise ValidationError()

    def to_value(self, value):
        return value.token


class SessionIDConverter(BaseConverter):
    regex = r"05[0-9a-fA-F]{64}"

    def to_python(self, value):
        return value


app.url_map.converters['Room'] = RoomTokenConverter
app.url_map.converters['SessionID'] = SessionIDConverter


@app.get("/")
def serve_index():
    rooms = model.get_readable_rooms()
    if len(rooms) == 0:
        return render_template('setup.html')
    return render_template(
        "index.html", url_base=config.URL_BASE, rooms=rooms, pubkey=crypto.server_pubkey_hex
    )


@app.get("/view/room/<Room:room>")
def view_room(room):
    if not room.default_read:
        abort(http.FORBIDDEN)

    return render_template(
        "view_room.html",
        room=room.token,
        room_url=utils.server_url(room.token),
        show_recent=config.HTTP_SHOW_RECENT,
    )


@app.get("/view/<Room:room>/invite.png")
def serve_invite_qr(room):
    if not room.default_read:
        abort(http.FORBIDDEN)

    img = qrencode.encode(utils.server_url(room.token))
    data = BytesIO()
    img = img[-1].resize((512, 512), NEAREST)
    img.save(data, "PNG")
    return Response(data.getvalue(), mimetype="image/png")


@app.post("/room/<Room:room>/message")
def post_to_room(room):
    user = utils.get_session_id(request)
    if not user:
        # todo: correct handling
        abort(http.FORBIDDEN)




@app.get("/room/<Room:room>/messages/recent")
def get_recent_room_messages(room):
    """get list of recent messages"""
    limit = utils.get_int_param('limit', 100, min=1, max=256)

    # FIXME: this is temporary, for the basic front-end; for proper implementation we should have a
    # user by this point.
    user = None

    if not room.check_permission(user, read=True):
        abort(http.FORBIDDEN)

    return utils.jsonify_with_base64(room.get_messages_for(user, recent=True, limit=limit))
