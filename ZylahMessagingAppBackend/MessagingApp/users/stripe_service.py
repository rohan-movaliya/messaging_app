import stripe
from django.conf import settings

stripe.api_key = settings.STRIPE_SECRET_KEY

def create_stripe_customer(email, payment_method_id):
    return stripe.Customer.create(
        email=email,
        payment_method=payment_method_id,
        invoice_settings={'default_payment_method': payment_method_id},
    )

def create_subscription(stripe_customer_id, price_id):
    return stripe.Subscription.create(
        customer=stripe_customer_id,
        items=[{'price': price_id}],  
        expand=['latest_invoice.payment_intent'],
    )

def cancel_subscription(stripe_subscription_id):
    return stripe.Subscription.delete(stripe_subscription_id)
