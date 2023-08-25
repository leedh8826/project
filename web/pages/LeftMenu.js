import React from 'react';

const LeftMenu = ({ onSelect }) => {
  return (
    <div className="left-menu">
      <button onClick={() => onSelect('menu1')}>Menu 1</button>
      <button onClick={() => onSelect('menu2')}>Menu 2</button>
    </div>
  );
};

export default LeftMenu;