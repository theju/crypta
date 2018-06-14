from django.http import HttpResponse


class CORSMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.method == "OPTIONS":
            response = HttpResponse()
            response["Access-Control-Allow-Credentials"] = "true"
            response["Access-Control-Allow-Headers"] = "authorization, content-type"
            response["Access-Control-Allow-Methods"] = "GET, POST, DELETE"
            response["Access-Control-Max-Age"] = 86400
        else:
            response = self.get_response(request)
        response["Access-Control-Allow-Origin"] = request.META.get("HTTP_ORIGIN")
        return response
