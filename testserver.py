import tornado.ioloop
import tornado.web
import asyncio
asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())  # python-3.8.0a4

PAGE = """
<html>
<head>
</head>
<body>
<h1>HEADER</h1>
DATA
<dir>
{getParam}
</dir>
<div>
{postParam}
</dir>
<form action="/" method="POST" name="test">
<input type="text" name="testin"/>
<input type="submit">
</form>
</body>
</html>
"""

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        getParam = 'getdef'
        try:
            getParam = self.get_argument('param', True)
        except:
            pass
        self.write(PAGE.format(getParam=getParam, postParam=''))
        
    def post(self):
        print(self.request.body)
        postParam = 'postdef'

        postParam = self.get_body_argument('testin')
        print(postParam)

        self.write(PAGE.format(getParam='', postParam=postParam))

def make_app():
    return tornado.web.Application([
        (r".*", MainHandler),
    ])

if __name__ == "__main__":
    app = make_app()
    app.listen(80)
    tornado.ioloop.IOLoop.current().start()