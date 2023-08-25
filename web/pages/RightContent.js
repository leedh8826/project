import React from 'react';

const RightContent = ({ selectedMenu, harmfulDomains, selectedDomains, handleCheckboxChange, handleAddDomain, handleDeleteSelectedDomains, domain, setDomain }) => {
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
      {selectedMenu === 'menu2' && <div>Content for Menu 2</div>}
    </div>
  );
};

export default RightContent;
