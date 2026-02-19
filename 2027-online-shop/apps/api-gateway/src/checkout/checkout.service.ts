import { Injectable } from '@nestjs/common';
import Stripe from 'stripe';

@Injectable()
export class CheckoutService {
    private stripe: Stripe;

    constructor() {
        // Should be process.env.STRIPE_SECRET_KEY, but falling back to test key if missing for compilation
        this.stripe = new Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_mock', {
            apiVersion: '2026-01-28.clover',
        });
    }

    async createPaymentIntent(amount: number, currency: string = 'eur') {
        // In production, validate stock here before creating intent
        const paymentIntent = await this.stripe.paymentIntents.create({
            amount: Math.round(amount * 100), // Convert to cents
            currency,
            automatic_payment_methods: {
                enabled: true,
            },
        });

        return {
            clientSecret: paymentIntent.client_secret,
        };
    }
}
