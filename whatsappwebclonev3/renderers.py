from ninja.renderers import BaseRenderer
import json

class MyCustomRenderer(BaseRenderer):
    media_type = "text/plain"

    def render(self, request, data, *, response_status):
        resp = data.get('detail')
        # print(resp)
        if isinstance(resp, list):
            errors = {}
            for r in resp:
                if r['loc'][0] == 'path':
                    errors[r['loc'][1]] = r['msg']
                elif r['loc'][0] == 'body':
                    errors[r['loc'][2]] = r['msg']
            return json.dumps({'errors': errors})
        return json.dumps(data)
