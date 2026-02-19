import { Controller, Post, Body } from '@nestjs/common';
import { CheckoutService } from './checkout.service';

@Controller('checkout')
export class CheckoutController {
    constructor(private readonly checkoutService: CheckoutService) { }

    @Post('create-payment-intent')
    createPaymentIntent(@Body() body: { amount: number }) {
        return this.checkoutService.createPaymentIntent(body.amount);
    }
}
