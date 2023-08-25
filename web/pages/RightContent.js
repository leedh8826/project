import React, { useState, useEffect } from 'react';

const RightContent = ({ selectedMenu, harmfulDomains, selectedDomains, handleCheckboxChange, 
                      handleAddDomain, handleDeleteSelectedDomains, domain, setDomain, 
                      pcapHarmfulLog, isLoading }) => {


  return (
    <div className="right-content">
      {selectedMenu === 'menu1' && (
        <div>
          <h1>Harmful Domain List</h1>
          {harmfulDomains && harmfulDomains.length > 0 ? (
            <ul>
              {harmfulDomains.map(domain => (
                <li key={domain.harmful_domain}>
                  <input
                    type="checkbox"
                    checked={selectedDomains.includes(domain.harmful_domain)}
                    onChange={e => handleCheckboxChange(e, domain.harmful_domain)}
                  />
                  {domain.harmful_domain}
                </li>
              ))}
            </ul>
          ) : (
            <p>No harmful domains found.</p>
          )}
          <p>
            <input
              type="text"
              placeholder="Enter domain"
              value={domain}
              onChange={e => setDomain(e.target.value)}
            />
            <button onClick={handleAddDomain}>Add Domain</button>
            <button onClick={handleDeleteSelectedDomains} disabled={selectedDomains.length === 0}>
              Delete Selected
            </button>
          </p>
        </div>
      )}
      {selectedMenu === 'menu2' && 
        <div>
          <h1>Harmful Domain List</h1>
          {isLoading ? (
            <p>Loading...</p>
          ) : (
            pcapHarmfulLog.length > 0 ? (
              <ul>
                {pcapHarmfulLog.map((domain, index) => (
                  <li key={index}>
                    Idx: {domain.pcap_index}
                    <ul>
                      <li>Domain: {domain.harmful_domain}</li>
                      <li>src_ip: {domain.src_ip}</li>
                      <li>des_ip: {domain.des_ip} </li>
                      <li>src_port: {domain.src_port} </li>
                      <li>des_port: {domain.des_port}</li>
                      <li>created_at: {domain.created_at}</li>
                    </ul>
                  </li>
                ))}
              </ul>
            ) : (
              <p>No domains in the log.</p>
            )
          )}
        </div>
      }
    </div>
  );
};

export default RightContent;
