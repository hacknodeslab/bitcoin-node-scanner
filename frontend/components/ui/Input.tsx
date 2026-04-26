import { InputHTMLAttributes, forwardRef } from "react";
import { cn } from "@/lib/utils";

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  function Input({ className, ...rest }, ref) {
    return (
      <input
        ref={ref}
        className={cn(
          "bg-bg text-text border border-border placeholder:text-dim",
          "px-[10px] py-[10px] text-body-sm w-full outline-none",
          "focus:border-text-dim",
          className,
        )}
        {...rest}
      />
    );
  },
);
