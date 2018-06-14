import json
import base64

from django.views import View
from django.shortcuts import render
from django.http import JsonResponse
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.contrib.sites.requests import RequestSite
from django.utils.translation import gettext_lazy as gl
from django.core.paginator import Paginator, InvalidPage
from django.views.decorators.http import require_http_methods

from .models import User, EncryptedRow
from .forms import RegisterForm, AuthForm


def home_page(request):
    return render(request, 'index.html', {
        'title': gl(settings.TITLE),
    })


def options(request):
    return render(request, 'options.html', {
        'title': gl(settings.TITLE),
        'domain': '{0}://{1}'.format(
            'https' if request.is_secure() else 'http',
            RequestSite(request).domain
        ),
    })

def manifest(request):
    return render(request, 'manifest.json', {
        'title': gl(settings.TITLE),
        'domain': '{0}://{1}'.format(
            'https' if request.is_secure() else 'http',
            RequestSite(request).domain
        ),
    },
                  content_type='application/json')


def authenticate(fn):
    def inner(request, **kwargs):
        authorization_header = request.META.get("HTTP_AUTHORIZATION", " ")
        auth_method, auth_details = authorization_header.split(" ", 1)
        if not auth_method.lower() == "basic":
            return JsonResponse(
                {"error": gl("Invalid authorization")},
                status=400
            )

        fingerprint, _ = base64.urlsafe_b64decode(auth_details.encode()).split(b":", 1)
        fingerprint = fingerprint.decode()
        try:
            user = User.objects.get(fingerprint=fingerprint)
        except User.DoesNotExist:
            return JsonResponse(
                {"error": gl("Invalid authorization")},
                status=400
            )
        data = {
            "public_key": user.public_key,
            "signature": request.POST.get("signature", ""),
            "message": request.POST.get("message", "")
        }
        form = AuthForm(data)
        if not form.is_valid():
            return JsonResponse({
                "error": form.errors
            }, status=400)

        kwargs["user"] = user
        return fn(request, **kwargs)
    return inner


@csrf_exempt
@require_http_methods(["POST"])
def register_user(request, **kwargs):
    form = RegisterForm(request.POST)
    if form.is_valid():
        user = User.objects.create(**form.cleaned_data)
    else:
        return JsonResponse({"error": form.errors}, status=400)
    return JsonResponse({})


@csrf_exempt
@require_http_methods(["POST"])
@authenticate
def unregister_user(request, **kwargs):
    user = kwargs["user"]
    EncryptedRow.objects.filter(user=user).delete()
    user.delete()
    return JsonResponse({})


@csrf_exempt
@require_http_methods(["POST"])
@authenticate
def get_row(request, **kwargs):
    user = kwargs["user"]
    key = request.POST.get("key")
    try:
        row = EncryptedRow.objects.get(user=user, key=key)
    except EncryptedRow.DoesNotExist:
        return JsonResponse({"error": gl("Not found")}, status=404)
    return JsonResponse({"key": row.key, "val": row.val})


@csrf_exempt
@require_http_methods(["POST"])
@authenticate
def create_row(request, **kwargs):
    user = kwargs["user"]
    key = request.POST.get("key")
    val = request.POST.get("val")
    try:
        row = EncryptedRow.objects.get(user=user, key=key)
        return JsonResponse({"error": gl("Key exists")}, status=400)
    except EncryptedRow.DoesNotExist:
        row = EncryptedRow.objects.create(user=user, key=key, val=val)
    return JsonResponse({"key": row.key, "val": row.val})


@csrf_exempt
@require_http_methods(["POST"])
@authenticate
def update_row(request, **kwargs):
    user = kwargs["user"]
    key = request.POST.get("key")
    val = request.POST.get("val")
    try:
        row = EncryptedRow.objects.get(user=user, key=key)
    except EncryptedRow.DoesNotExist:
        return JsonResponse({"error": gl("Not found")}, status=404)
    row.val = val
    row.save()
    return JsonResponse({"key": row.key, "val": row.val})


@csrf_exempt
@require_http_methods(["POST"])
@authenticate
def delete_row(request, **kwargs):
    user = kwargs["user"]
    key = request.POST.get("key")
    val = request.POST.get("val")
    try:
        row = EncryptedRow.objects.get(user=user, key=key)
    except EncryptedRow.DoesNotExist:
        return JsonResponse({"error": gl("Not found")}, status=404)
    row.delete()
    return JsonResponse({})


@csrf_exempt
@require_http_methods(["POST"])
@authenticate
def export_rows(request, **kwargs):
    user = kwargs["user"]
    try:
        page_num = int(request.POST.get("page"))
    except (ValueError, TypeError):
        page_num = 1

    PER_PAGE = 10
    try:
        count = int(request.POST.get("count"))
    except (ValueError, TypeError):
        count = PER_PAGE
    if count > PER_PAGE:
        count = PER_PAGE

    output = {}

    qs = EncryptedRow.objects.filter(user=user)
    paginator = Paginator(qs, count, allow_empty_first_page=False)

    try:
        rows = paginator.get_page(page_num)
        if rows.has_next():
            output['next_page'] = rows.next_page_number()
        if rows.has_previous():
            output['prev_page'] = rows.previous_page_number()
    except InvalidPage:
        rows = Paginator([], count).get_page(1)

    output_rows = []
    for row in rows.object_list:
        output_rows.append({"key": row.key, "val": row.val})
    output['rows'] = output_rows
    return JsonResponse(output)
