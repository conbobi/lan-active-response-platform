import React, { useState, useRef, useEffect, useCallback } from 'react';
import { FiChevronDown } from 'react-icons/fi';

export default function Dropdown({
  label,
  options = [],
  value,
  onChange,
  triggerStyle,
  className = '',
  disabled = false,
}) {
  const [open, setOpen] = useState(false);
  const [highlightedIndex, setHighlightedIndex] = useState(-1);
  const ref = useRef(null);
  const listRef = useRef(null);

  const selectedIndex = options.findIndex((o) => o.value === value);
  const selected = selectedIndex >= 0 ? options[selectedIndex] : null;

  // Sync highlightedIndex with current selection when opening
  useEffect(() => {
    if (open) {
      setHighlightedIndex(selectedIndex >= 0 ? selectedIndex : 0);
    } else {
      setHighlightedIndex(-1);
    }
  }, [open, selectedIndex]);

  // Scroll highlighted item into view
  useEffect(() => {
    if (open && listRef.current && highlightedIndex >= 0) {
      const items = listRef.current.querySelectorAll('.dropdown-item');
      if (items[highlightedIndex]) {
        items[highlightedIndex].scrollIntoView({ block: 'nearest' });
      }
    }
  }, [open, highlightedIndex]);

  // Click outside to close without selecting
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (ref.current && !ref.current.contains(e.target)) {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleSelect = useCallback(
    (val) => {
      if (onChange) onChange(val);
      setOpen(false);
    },
    [onChange]
  );

  const handleKeyDown = (e) => {
    if (disabled) return;

    if (!open) {
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp' || e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        setOpen(true);
      }
      return;
    }

    // Keyboard navigation when dropdown is open
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        setHighlightedIndex((prev) => (prev + 1) % options.length);
        break;
      case 'ArrowUp':
        e.preventDefault();
        setHighlightedIndex((prev) => (prev - 1 + options.length) % options.length);
        break;
      case 'Enter':
      case ' ':
        e.preventDefault();
        if (highlightedIndex >= 0 && highlightedIndex < options.length) {
          handleSelect(options[highlightedIndex].value);
        }
        break;
      case 'Escape':
      case 'Tab':
        setOpen(false);
        break;
      default:
        break;
    }
  };

  const toggleDropdown = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (!disabled) {
      setOpen((prev) => !prev);
    }
  };

  return (
    <div
      className={`dropdown ${className}`}
      ref={ref}
      onKeyDown={handleKeyDown}
      style={{ outline: 'none' }}
    >
      <button
        type="button"
        className={`dropdown-trigger ${open ? 'open' : ''}`}
        onClick={toggleDropdown}
        disabled={disabled}
        style={triggerStyle}
        aria-haspopup="listbox"
        aria-expanded={open}
      >
        <span>{selected ? selected.label : label}</span>
        <FiChevronDown size={14} className={`dropdown-arrow ${open ? 'open' : ''}`} />
      </button>

      {open && (
        <div className="dropdown-menu" ref={listRef} role="listbox">
          {options.map((opt, idx) => {
            const isSelected = opt.value === value;
            const isHighlighted = idx === highlightedIndex;

            return (
              <button
                type="button"
                key={opt.value}
                role="option"
                aria-selected={isSelected}
                className={`dropdown-item ${isSelected ? 'selected' : ''} ${
                  isHighlighted ? 'highlighted' : ''
                }`}
                onClick={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  handleSelect(opt.value);
                }}
                onMouseEnter={() => setHighlightedIndex(idx)}
              >
                {opt.label}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
