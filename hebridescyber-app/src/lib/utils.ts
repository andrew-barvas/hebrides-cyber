import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/** Joins class names and lets later Tailwind utilities override earlier
 *  conflicting ones, so a primitive's defaults can be overridden via
 *  `className` (e.g. `<Card className="p-0">` actually removes the padding). */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
