import React from 'react';

import styles from ".//style.module.css";

const LeftMenu = ({ onSelect }) => {
  return (
    <div className="left-menu">
      <button className={styles['list']} onClick={() => onSelect('menu1')}>차단 도메인</button>
      <button className={styles['log']} onClick={() => onSelect('menu2')}>차단 로그</button>
    </div>
  );
};

export default LeftMenu;