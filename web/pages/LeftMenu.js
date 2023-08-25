import React from 'react';
import styles from ".//style.module.css";
const LeftMenu = ({ onSelect }) => {
  return (
    <div className={styles['div_left']}>
      <button className={styles['log']} onClick={() => onSelect('menu1')}>Menu 1</button>
      <button className={styles['list']} onClick={() => onSelect('menu2')}>Menu 2</button>
    </div>
  );
};

export default LeftMenu;