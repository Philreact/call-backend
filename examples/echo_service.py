from qapp_backend import QAppServer

server = QAppServer()


@server.rpc("/hello")
def hello(ctx, payload):
    return {"message": "hello"}


@server.on_message("echo")
def echo(ctx, payload):
    ctx.session.send({"type": "echo", "payload": payload})


if __name__ == "__main__":
    server.run()
