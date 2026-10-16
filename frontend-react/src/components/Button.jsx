import React from 'react';
/**
 * Button – reusable styled button.
 * Props:
 *   - children: button label/content
 *   - onClick: click handler
 *   - type: button type (default 'button')
 *   - variant: 'primary' | 'secondary' (default 'primary')
 *   - disabled: boolean
 *   - className: additional Tailwind classes
 *   - as: component or string to render as (e.g., 'a' or Link component)
 *   - href: when using an 'a' element
 */
const Button = ({
  children,
  onClick,
  type = 'button',
  variant = 'primary',
  disabled = false,
  className = '',
  as: Component = 'button',
  href,
  ...rest
}) => {
  const baseStyles = 'px-4 py-2 rounded focus:outline-none focus:ring-2 focus:ring-offset-2';
  const variants = {
    primary: 'bg-blue-600 text-white hover:bg-blue-700 focus:ring-blue-500',
    secondary: 'bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-100 hover:bg-gray-300 dark:hover:bg-gray-600 focus:ring-gray-500',
  };
  const variantClasses = variants[variant] || variants.primary;
  const disabledClasses = disabled ? 'opacity-50 cursor-not-allowed' : '';

  const props = {
    className: `${baseStyles} ${variantClasses} ${disabledClasses} ${className}`,
    disabled,
    onClick,
    ...rest,
  };

  if (Component === 'a' && href) {
    props.href = href;
    props.role = 'button';
  }

  return (
    <Component type={Component === 'button' ? type : undefined} {...props}>
      {children}
    </Component>
  );
};

export default Button;
