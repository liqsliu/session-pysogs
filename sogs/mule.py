import traceback
import oxenmq
from oxenc import bt_deserialize
import time
from datetime import timedelta
import functools

from .web import app
from . import cleanup
from . import config
from . import omq as o

# This is the uwsgi "mule" that handles things not related to serving HTTP requests:
# - it holds the oxenmq instance (with its own interface into sogs)
# - it handles cleanup jobs (e.g. periodic deletions)





    ##############################
from sogs import utils
from sogs import model

#from nacl.public import PrivateKey
class TestUser(model.User):
    def __init__(self, key):
#        self.privkey = PrivateKey.generate()
        self.privkey = key

        super().__init__(session_id="05" + self.privkey.public_key.encode().hex(), touch=True)


from typing import Union


def pad32(data: Union[bytes, str]):
    """Returns the bytes (or str.encode()) padded to length 32 by appending null bytes"""
    if isinstance(data, str):
        data = data.encode()
    assert len(data) <= 32
    if len(data) < 32:
        return data + b'\0' * (32 - len(data))
    return data


import sogs.session_pb2
def parse_message(data: bytes):
    msg = sogs.session_pb2.Content()
    try:
      msg.ParseFromString(utils.remove_session_message_padding(data))
    except:
        pass
        return
    return msg.dataMessage

myid = "053ecfa4c331566e2af8b71a25a0983613860bedcc833cf9099f36725926de2237"
me = model.User(session_id=myid)
sid = "055955da2564006e943f49c18d8f8e8c0ef177450234b573dbf6748eb7dbb87c72"
server = model.User(session_id=sid)
import sogs.crypto
bot = TestUser(sogs.crypto.bot_key)
bot = TestUser(sogs.crypto.server_key)

user = server
user = bot

rooms = model.get_rooms()
if rooms:
    for room in rooms:
        pass
       # print_room(room)
else:
    print("No rooms.")
    room=None




def get_headers(data):
    from json import dumps
#    r = sogs_post(client, url_post, {"data": d, "signature": s}, user)
#    d, s = (utils.encode_base64(x) for x in (b"post 1", pad32("sig 1")))
#    data={"data": d, "signature": s}
    print(data)
    try:
        data = dumps(data).encode()
    except:
        pass
    from .auth import x_sogs_for
    url = "/room/wtfipfs/message"

    headers=x_sogs_for(user, "POST", url, data)
    print(headers)
    return data, headers

sent=0
#def test_posting(client, room, user, user2, mod, global_mod):
def my_test():
    global sent
    if sent == 0:
        sent = 1
    else:
      return

#    msgs = root
#    msgs = room.get_messages_for(user, recent=True, limit=4)
#    msgs = room.get_messages_for(user, single=63, limit=1)
    msgs = room.get_messages_for(user, single=67, limit=1)
    for msg in msgs:
#      print(msg)
#      print(utils.message_body(msg["data"]))
#      print(utils.remove_session_message_padding(msg["data"]))
#      print(msg["data"].decode())
#    msgs = utils.jsonify_with_base64(msgs)
#    msgs = utils.json_with_base64(msgs)
#        print(parse_message(msg["data"]))
        print(msg)
        print(msg["data"])
        print(len(msg["data"]))
        print(len(msg['signature']))
        msg=parse_message(msg["data"])
        print(msg.ByteSize())
        print(msg)


#    time.sleep(5)
#    msg = "test"
    d, s = (utils.encode_base64(x) for x in (b"post 1", pad32("sig 1")))
    #user = TestUser()
    data={
        "body": "test",
        "expireTimer": 0,
        "profile": {
          "displayName": "bot"
          }
        }


#    msg = sogs.session_pb2.Content().CopyFrom(msg)
    tmp = str(msg).encode()
    print(tmp)
#    tmp = msg.SerializePartialToString()
    tmp = msg.SerializeToString()
    tmp = b"\n"+chr(msg.ByteSize()).encode()+tmp
    print(repr(tmp))
#    msg = sogs.session_pb2.Content()
#    msg = sogs.session_pb2.DataMessage()
#    msg.ParseFromString(tmp)
    msg.body="test"
    msg.profile.displayName="bot"
#    data=str(msg).encode()
    data = msg.SerializeToString()
    data = b"\n"+chr(msg.ByteSize()).encode()+data

    d, h = get_headers(data)
#    data = utils.add_session_message_padding(data, msg.ByteSize())
    d = utils.add_session_message_padding(d, 159)
    d = utils.encode_base64(d)
    s = h["X-SOGS-Hash"]

    msg = room.add_post(
      user=user,
#      data=utils.decode_base64(req.get('data')),
  #    whisper_to=req.get('whisper_to'),
  #    whisper_mods=bool(req.get('whisper_mods')),
#      sig=utils.decode_base64(req.get('signature')),
      data=utils.decode_base64(d),
      sig=utils.decode_base64(s)
#      data=data,
#      sig=req["X-SOGS-Hash"],
    )
    print(msg)

    return

    from sogs import web
    with web.app.test_client() as client:
        pass
        client.post( url, data=data, content_type='application/json', headers=x_sogs_for(user, "POST", url, data))



def run():
    try:
        app.logger.info("OxenMQ mule started.")

        my_test()
        while True:
            time.sleep(1)

    except Exception:
        app.logger.error("mule died via exception:\n{}".format(traceback.format_exc()))


def allow_conn(addr, pk, sn):
    # TODO: user recognition auth
    return oxenmq.AuthLevel.basic


def admin_conn(addr, pk, sn):
    return oxenmq.AuthLevel.admin


def inproc_fail(connid, reason):
    raise RuntimeError(f"Couldn't connect mule to itself: {reason}")


def setup_omq():
    omq = o.omq

    app.logger.debug("Mule setting up omq")
    if isinstance(config.OMQ_LISTEN, list):
        listen = config.OMQ_LISTEN
    elif config.OMQ_LISTEN is None:
        listen = []
    else:
        listen = [config.OMQ_LISTEN]
    for addr in listen:
        omq.listen(addr, curve=True, allow_connection=allow_conn)
        app.logger.info(f"OxenMQ listening on {addr}")

    # Internal socket for workers to talk to us:
    omq.listen(config.OMQ_INTERNAL, curve=False, allow_connection=admin_conn)

    # Periodic database cleanup timer:
    omq.add_timer(cleanup.cleanup, timedelta(seconds=cleanup.INTERVAL))

    # Commands other workers can send to us, e.g. for notifications of activity for us to know about
    worker = omq.add_category("worker", access_level=oxenmq.AuthLevel.admin)
    worker.add_command("message_posted", message_posted)
    worker.add_command("messages_deleted", messages_deleted)
    worker.add_command("message_edited", message_edited)

    app.logger.debug("Mule starting omq")
    omq.start()

    # Connect mule to itself so that if something the mule does wants to send something to the mule
    # it will work.  (And so be careful not to recurse!)
    app.logger.debug("Mule connecting to self")
    o.mule_conn = omq.connect_inproc(on_success=None, on_failure=inproc_fail)


def log_exceptions(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            app.logger.error(f"{f.__name__} raised exception: {e}")
            raise

    return wrapper



from .mt import mt_send


@log_exceptions
def message_posted(m: oxenmq.Message):
    id = bt_deserialize(m.data()[0])
    print("55555")
    print(m)
    print(len(m.data()))
    print("----")
    for i in m.data():
        print(bt_deserialize(i))
        print("----")
    print(list(m.data()))
    print(dir(m))
    msgs = room.get_messages_for(bot, single=int(id), limit=1)
    print("----")
    for msg in msgs:
#      print(msg)
#      print(utils.message_body(msg["data"]))
#      print(utils.remove_session_message_padding(msg["data"]))
        print(msg)
        print("--")
        msg=parse_message(msg["data"])
        print(msg)
#        mt_send(text=msg["body"], username="S "+msg["profile"]["displayName"])
        mt_send(text=msg.body, username="S "+msg.profile.displayName)
        print("----")
    app.logger.warning(f"FIXME: mule -- message posted stub, id={id}")


@log_exceptions
def messages_deleted(m: oxenmq.Message):
    ids = bt_deserialize(m.data()[0])
    print("55555")
    print(m)
    app.logger.warning(f"FIXME: mule -- message delete stub, deleted messages: {ids}")


@log_exceptions
def message_edited(m: oxenmq.Message):
    app.logger.warning("FIXME: mule -- message edited stub")
