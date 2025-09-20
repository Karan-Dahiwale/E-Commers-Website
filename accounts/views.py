from django.shortcuts import render,redirect
from .forms import RegistrationForm
from .models import Account
from django.contrib import messages,auth
from django.contrib.auth.decorators import login_required
from django.contrib import messages, auth
from django.shortcuts import render, redirect

#varification email
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage

from carts.views import _cart_id
from carts.models import Cart,CartItem
import requests
from urllib.parse import urlparse, parse_qs


# Create your views here.
def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            phone_number = form.cleaned_data['phone_number']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            username = email.split('@')[0]

            user = Account.objects.create_user(
                first_name=first_name,
                last_name=last_name,
                email=email,
                username=username,
                password=password
            )
            user.phone_number = phone_number
            user.save()

            #user actiavte
            current_site = get_current_site(request)
            mail_subject = 'Please activate your account'
            message = render_to_string('accounts/account_varification_email.html', {
                'user': user,
                'domain': current_site.domain,  # use .domain here
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })
            to_email = email
            email_message = EmailMessage(mail_subject, message, to=[to_email])
            email_message.send()


            #messages.success(request, 'thank you for registering with us we sent you a varification email on your email address')
            return redirect(f'/accounts/login/?command=verification&email={email}')

    else:
        form = RegistrationForm()
    context = {
        'form': form,
    }
    return render(request, 'accounts/register.html', context)




def login(request):
    if request.method == 'POST':
        email = request.POST['email'].lower()
        password = request.POST['password']

        user = auth.authenticate(email=email, password=password)

        if user is not None:
            try:
                # Get the guest cart
                cart = Cart.objects.get(cart_id=_cart_id(request))
                cart_items = CartItem.objects.filter(cart=cart)

                if cart_items.exists():
                    # Variations in guest cart
                    guest_var_list = []
                    guest_ids = []
                    for item in cart_items:
                        guest_var_list.append(list(item.variations.all()))
                        guest_ids.append(item.id)

                    # Variations in user cart
                    user_cart_items = CartItem.objects.filter(user=user)
                    user_var_list = []
                    user_ids = []
                    for item in user_cart_items:
                        user_var_list.append(list(item.variations.all()))
                        user_ids.append(item.id)

                    # Merge guest cart into user cart
                    for idx, variation in enumerate(guest_var_list):
                        if variation in user_var_list:
                            index = user_var_list.index(variation)
                            item_id = user_ids[index]
                            item = CartItem.objects.get(id=item_id)
                            item.quantity += 1
                            item.save()
                        else:
                            # Assign guest cart items to the user
                            guest_item = CartItem.objects.get(id=guest_ids[idx])
                            guest_item.user = user
                            guest_item.cart = None  # clear guest cart link
                            guest_item.save()

            except Cart.DoesNotExist:
                pass

            auth.login(request, user)
            messages.success(request, 'You are now logged in.')
            url = request.META.get('HTTP_REFERER')
            try:
                query = requests.utils.urlparse(url).query
                # next=/cart/checkout/
                params = dict(x.split('=') for x in query.split('&'))
                if 'next' in params:
                    nextPage = params['next']
                    return redirect(nextPage)
            except:
                return redirect('dashboard')
        else:
            messages.error(request, 'Invalid login credentials')
            return redirect('login')
    return render(request, 'accounts/login.html')


@login_required(login_url='login')
def logout(request):
    # Clear previous messages
    storage = messages.get_messages(request)
    for _ in storage:
        pass  # Iterating clears old messages

    auth.logout(request)
    messages.success(request, 'You are logged out.')
    return redirect('login')

def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except (TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, 'Congratulations, your account has been activated.')
        return redirect('login')
    else:
        messages.error(request, 'Invalid activation link.')
        return redirect('register')

@login_required(login_url='login')
def dashboard(request):
    return render(request, 'accounts/dashboard.html')

    
def forgotpassword(request):
    if request.method == 'POST':
        email=request.POST['email']
        if Account.objects.filter(email=email).exists():
            user = Account.objects.get(email__exact=email)
            # reset password email
            current_site = get_current_site(request)
            mail_subject = 'reset your password'
            message = render_to_string('accounts/reset_password_email.html', {
                'user': user,
                'domain': current_site.domain,  # use .domain here
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })
            to_email = email
            email_message = EmailMessage(mail_subject, message, to=[to_email])
            email_message.send()
            
            messages.success(request, 'password reset email has been sent to your email address')
            return redirect('login')

        else:
            messages.error(request, 'Account Does Not exist')
            return redirect('forgotpassword')    

    return render(request, 'accounts/forgotpassword.html')


def resetpassword_validate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except (TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None
    
    if user is not None and default_token_generator.check_token(user, token):
        request.session['uid'] = uid
        messages.success(request, 'Please reset your password.')
        return redirect('resetpassword')  # make sure this matches your URL name
    else:
        messages.error(request, 'This link has expired.')
        return redirect('login')
    
def resetpassword(request):
    if request.method == 'POST':
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        if password == confirm_password:
            uid = request.session.get('uid')
            if uid is None:
                messages.error(request, "Session expired. Please try again.")
                return redirect('forgotpassword')

            try:
                user = Account.objects.get(pk=uid)
                user.set_password(password)
                user.save()
                messages.success(request, 'Password reset successful.')
                # Clear uid from session
                del request.session['uid']
                return redirect('login')
            except Account.DoesNotExist:
                messages.error(request, 'User does not exist.')
                return redirect('forgotpassword')
        else:
            messages.error(request, 'Passwords do not match.')
            return redirect('resetpassword')
    else:
        return render(request, 'accounts/resetpassword.html')