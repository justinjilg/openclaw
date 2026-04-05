To create Jest tests for a React frontend using React Testing Library, you'll want to cover a range of tests including component tests, hook tests, and snapshot tests. Below is a sample structure to guide you through the testing process:

### Component Tests

Suppose you have a simple React component like this:

```jsx
// Button.js
import React from 'react';

const Button = ({ label, onClick }) => {
  return <button onClick={onClick}>{label}</button>;
};

export default Button;
```

You would write a component test like this:

```jsx
// Button.test.js
import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import Button from './Button';

describe('Button component', () => {
  it('renders with the correct label', () => {
    render(<Button label="Click Me" />);
    expect(screen.getByText('Click Me')).toBeInTheDocument();
  });

  it('calls onClick handler when clicked', () => {
    const handleClick = jest.fn();
    render(<Button label="Click Me" onClick={handleClick} />);
    fireEvent.click(screen.getByText('Click Me'));
    expect(handleClick).toHaveBeenCalledTimes(1);
  });
});
```

### Hook Tests

If you have a custom hook, you might want to test it independently. For example:

```jsx
// useCounter.js
import { useState } from 'react';

export const useCounter = (initialValue = 0) => {
  const [count, setCount] = useState(initialValue);

  const increment = () => setCount((c) => c + 1);
  const decrement = () => setCount((c) => c - 1);

  return { count, increment, decrement };
};
```

You can test it using `@testing-library/react-hooks`:

```jsx
// useCounter.test.js
import { renderHook, act } from '@testing-library/react-hooks';
import { useCounter } from './useCounter';

describe('useCounter hook', () => {
  it('should initialize counter with default value', () => {
    const { result } = renderHook(() => useCounter());
    expect(result.current.count).toBe(0);
  });

  it('should increment counter', () => {
    const { result } = renderHook(() => useCounter(5));
    act(() => {
      result.current.increment();
    });
    expect(result.current.count).toBe(6);
  });

  it('should decrement counter', () => {
    const { result } = renderHook(() => useCounter(5));
    act(() => {
      result.current.decrement();
    });
    expect(result.current.count).toBe(4);
  });
});
```

### Snapshot Tests

For snapshot testing, you can use Jest's `toMatchSnapshot` feature to ensure the UI doesn't change unexpectedly. Consider the same `Button` component:

```jsx
// Button.snapshot.test.js
import React from 'react';
import { render } from '@testing-library/react';
import Button from './Button';

describe('Button Snapshot', () => {
  it('renders correctly', () => {
    const { asFragment } = render(<Button label="Snapshot" />);
    expect(asFragment()).toMatchSnapshot();
  });
});
```

### Setup and Running Tests

1. **Install Dependencies**: Make sure you have Jest and React Testing Library installed:

   ```bash
   npm install --save-dev jest @testing-library/react @testing-library/react-hooks
   ```

2. **Configure Jest**: Ensure your `package.json` or Jest config includes the appropriate settings for React Testing Library.

3. **Run Tests**: Use the following command to run your tests:

   ```bash
   npm test
   ```

This covers the basics of component, hook, and snapshot tests using Jest and React Testing Library. You can extend these tests as needed for your components and application logic.
