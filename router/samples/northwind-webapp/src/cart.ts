// northwind-webapp — shopping cart helpers (synthetic sample, MIT)

export interface LineItem {
  sku: string;
  name: string;
  unitPrice: number;
  qty: number;
}

export function subtotal(items: LineItem[]): number {
  return items.reduce((sum, it) => sum + it.unitPrice * it.qty, 0);
}

export function applyDiscount(amount: number, percentOff: number): number {
  const clamped = Math.max(0, Math.min(100, percentOff));
  return Math.round(amount * (1 - clamped / 100) * 100) / 100;
}

export function withTax(amount: number, taxRate: number): number {
  return Math.round(amount * (1 + taxRate) * 100) / 100;
}

export function cartTotal(items: LineItem[], percentOff = 0, taxRate = 0.0875): number {
  return withTax(applyDiscount(subtotal(items), percentOff), taxRate);
}
