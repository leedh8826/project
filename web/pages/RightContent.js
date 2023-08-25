import React from 'react';
import styles from ".//style.module.css";
//import '../styled-jsx/global.css';
function VerticalLine({ className }) {
  return <div className={`${styles['vertical-line']} ${className}`}></div>;
}
const RightContent = ({ DomainLogPage,selectedMenu, harmfulDomains, selectedDomains, handleCheckboxChange, handleAddDomain, 
                        handleDeleteSelectedDomains, domain, setDomain, pcapHarmfulLog, isLoading }) => {
  return (
    <div className="right-content">
      {selectedMenu === 'menu1' && (
         <div>
         
         <h2> Solution Development Phase1 </h2>
         <hr></hr>
         <VerticalLine className={styles['vertical-line']} />
         {harmfulDomains && harmfulDomains.length > 0 ? (
             <table  className={styles['table_set']}>
                 
             <caption>차단 로그</caption>
             <colgroup>
                 <col width='8%' />
                 <col width='*%' />
                 <col width='15%' />
                 <col width='15%' />
             </colgroup>
             <thead> 
                 <tr className={styles['table_set']}>
                   
                     <th>도메인 주소</th>
                     <th>추가 날짜</th> 
                     <th>체크</th>
                    
                 </tr>
                 {harmfulDomains.map(domain => (
                 <tr>
                    
                   
 
                     <th>
                         {domain.harmful_domain}
                     </th>
                     <th>
                         {domain.datetime}
                     </th>  
                     <th>
                         <input
                             type="checkbox"
                             checked={selectedDomains.includes(domain.harmful_domain)}
                             onChange={e => handleCheckboxChange(e, domain.harmful_domain)}
                         />
 
                     </th>
                 </tr>
                 ))}
             </thead>
             <tbody>
             
             </tbody>
         </table>   
         
         ) : (
             <p>No harmful domains found.</p>
         )}
         <p className={styles['input_box']}>
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
            <div className={styles['main']}><a href='/'>메인 페이지</a></div>
            <div className={styles['log']}><a href='/domain_log'>접속 기록</a></div>
            <div className={styles['list']}>차단 도메인</div>
            <h2> Solution Development Phase1 </h2>
            <hr></hr>
            <VerticalLine className={styles['vertical-line']} />

            {DomainLogPage.isLoading ? (
                <p>Loading...</p>
            ) : (
                pcapHarmfulLog.length > 0 ? (
                    <table className={styles['table_set']}>
                         <caption>차단 로그</caption>
                        <colgroup>
                            <col width='8%' />
                            <col width='*%' />
                            <col width='15%' />
                            <col width='15%' />
                        </colgroup>
                        <tr>
                        <th>domain</th> 
                                <th>src_ip</th>
                                <th>des_ip </th>
                                <th>src_port</th>
                                <th>des_port</th>
                                <th>created_at</th>
                        </tr>
                    {pcapHarmfulLog.map((domain, index) => (
                      
                            <tr>
                                <th>{domain.harmful_domain}</th> 
                                <th>{domain.src_ip}</th>
                                <th>{domain.des_ip} </th>
                                <th>{domain.src_port} </th>
                                <th>{domain.des_port}</th>
                                <th>{domain.created_at}</th>
                            </tr>

                    ))}
                    </table>
                ) : (
                    <p>No domains in the log.</p>
                )
            )}
        </div>}
    </div>
  );
};

export default RightContent;
