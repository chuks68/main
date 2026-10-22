import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { axe } from 'jest-axe';
import { LineageGraph, LineageNode } from './LineageGraph';

const nodes: LineageNode[] = [
  { id: 'root', label: 'Orders', parentId: null, children: ['customer', 'items'] },
  { id: 'customer', label: 'Customers', parentId: 'root', children: [] },
  { id: 'items', label: 'Order Items', parentId: 'root', children: ['product'] },
  { id: 'product', label: 'Products', parentId: 'items', children: [] },
];

describe('LineageGraph keyboard navigation', () => {
  it('renders nodes as treeitems within a tree', () => {
    render(<LineageGraph nodes={nodes} />);
    const tree = screen.getByRole('tree');
    expect(tree).toBeInTheDocument();
    const items = screen.getAllByRole('treeitem');
    expect(items.length).greaterThan(0);
    expect(items[0]).toHaveAttribute('aria-level', '1');
  });

  it('announces node label and depth', () => {
    render(<LineageGraph nodes={nodes} />);
    const root = screen.getByRole('treeitem', { name: /Orders, depth 1/ });
    expect(root).toBeInTheDocument();
  });

  it('moves focus with arrow keys and opens on Enter', () => {
    const onNodeOpen = jest.fn();
    render(<LineageGraph nodes={nodes} onNodeOpen={onNodeOpen} />);
    const tree = screen.getByRole('tree');
    const root = screen.getByRole('treeitem', { name: /Orders, depth 1/ });
    root.focus();
    fireEvent.keyDown(tree, { key: 'ArrowDown' });
    const customers = screen.getByRole('treeitem', { name: /Customers, depth 2/ });
    expect(customers).toHaveFocus();
    fireEvent.keyDown(tree, { key: 'ArrowUp' });
    expect(root).toHaveFocus();
    fireEvent.keyDown(tree, { key: 'Enter' });
    expect(onNodeOpen).toHaveBeenCalledWith(expect.objectContaining({ id: 'root' }));
  });

  it('expands and collapses with left/right arrows', () => {
    render(<LineageGraph nodes={nodes} />);
    const tree = screen.getByRole('tree');
    const root = screen.getByRole('treeitem', { name: /Orders, depth 1/ });
    root.focus();
    expect(root).toHaveAttribute('aria-expanded', 'true');
    fireEvent.keyDown(tree, { key: 'ArrowLeft' });
    expect(root).toHaveAttribute('aria-expanded', 'false');
    fireEvent.keyDown(tree, { key: 'ArrowRight' });
    expect(root).toHaveAttribute('aria-expanded', 'true');
  });

  it('passes axe checks', async () => {
    const { container } = render(<LineageGraph nodes={nodes} />);
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
});
