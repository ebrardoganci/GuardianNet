from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.forms import AuthenticationForm
from django.shortcuts import redirect, render
from django.utils.http import url_has_allowed_host_and_scheme


def login_view(request):
    if request.user.is_authenticated:
        return redirect("dashboard:index")
    next_url = request.GET.get("next", "")
    form = AuthenticationForm(request, data=request.POST or None)
    if request.method == "POST":
        next_url = request.POST.get("next") or request.GET.get("next") or ""
        if form.is_valid():
            login(request, form.get_user())
            if next_url and url_has_allowed_host_and_scheme(next_url, {request.get_host()}, require_https=request.is_secure()):
                return redirect(next_url)
            return redirect("dashboard:index")
        messages.error(request, "Kullanici adi veya sifre hatali.")
    return render(request, "accounts/login.html", {"form": form, "next": next_url})


def logout_view(request):
    logout(request)
    messages.success(request, "Basariyla cikis yaptiniz.")
    return redirect("login")
