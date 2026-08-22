import React from 'react';

export default function Button({
  children, onClick, variant = 'primary', size = 'md',
  disabled = false, type = 'button', className = '', style = {},
  iconLeft, iconRight,
}) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      style={style}
      className={`btn btn-${variant} btn-${size} ${className}`}
    >
      {iconLeft && iconLeft}
      {children}
      {iconRight && iconRight}
    </button>
  );
}
