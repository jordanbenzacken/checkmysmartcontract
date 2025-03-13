import React from 'react';
import { loadStripe } from '@stripe/stripe-js';
import { X } from 'lucide-react';

interface PaymentModalProps {
  isOpen: boolean;
  onClose: () => void;
  price: number;
}

const stripePromise = loadStripe(import.meta.env.VITE_STRIPE_PUBLIC_KEY);

export function PaymentModal({ isOpen, onClose, price }: PaymentModalProps) {
  if (!isOpen) return null;

  const handlePayment = async () => {
    const stripe = await stripePromise;
    if (!stripe) return;

    // Here you would typically make an API call to your backend to create a Stripe session
    // For demo purposes, we'll just show an alert
    alert('In production, this would redirect to Stripe payment');
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4">
      <div className="bg-white rounded-lg p-6 max-w-md w-full relative">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-gray-500 hover:text-gray-700"
        >
          <X size={24} />
        </button>
        
        <h2 className="text-2xl font-bold mb-4">Subscribe to Access</h2>
        <p className="text-gray-600 mb-6">
          Get unlimited access to our factorial calculator for just ${price}/month
        </p>
        
        <div className="bg-gray-50 p-4 rounded-lg mb-6">
          <div className="flex justify-between mb-2">
            <span>Monthly subscription</span>
            <span>${price}</span>
          </div>
          <div className="text-sm text-gray-500">
            Cancel anytime. Instant access after payment.
          </div>
        </div>

        <button
          onClick={handlePayment}
          className="w-full bg-blue-600 text-white py-3 px-4 rounded-lg hover:bg-blue-700 transition-colors"
        >
          Subscribe Now
        </button>
        
        <p className="text-xs text-gray-500 text-center mt-4">
          Secure payment powered by Stripe
        </p>
      </div>
    </div>
  );
}