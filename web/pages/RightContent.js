import React from 'react';
import styles from ".//style.module.css";
//import '../styled-jsx/global.css';

const RightContent = ({ DomainLogPage,selectedMenu, harmfulDomains, selectedDomains, handleCheckboxChange, handleAddDomain, 
                        handleDeleteSelectedDomains, domain, setDomain, pcapHarmfulLog, isLoading }) => {
  return (
    <div>
      <div>
        
             <h2> Solution Development Phase1 </h2>
             <hr></hr>
          </div>
      {selectedMenu === 'menu1' && (
        <div>
          {harmfulDomains && harmfulDomains.length > 0 ? (
             <table className={styles['table_set']}>
                 
             <thead > 
                 <tr className={styles['table_st']}>
                   
                     <td className={styles['table_st']}>도메인 주소</td>
                     <td className={styles['table_st']}>추가 날짜</td> 
                     <td className={styles['table_st']}>체크</td>
                    
                 </tr>
                 {harmfulDomains.map(domain => (
                 <tr>
                     <td className={styles['row_st']}>{domain.harmful_domain} </td>
                     <td className={styles['row_st']}>{domain.datetime}</td>  
                     <td className={styles['row_st']}>
                         <input
                             type="checkbox"
                             checked={selectedDomains.includes(domain.harmful_domain)}
                             onChange={e => handleCheckboxChange(e, domain.harmful_domain)}
                         />
 
                     </td>
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
           
            <div>
            {DomainLogPage.isLoading ? (
                <p>Loading...</p>
            ) : (
                pcapHarmfulLog.length > 0 ? (
                    <table className={styles['table_set']}>

                        <tr>
                                <td className={styles['table_st']}>도메인</td> 
                                <td className={styles['table_st']}>출발지IP</td>
                                <td className={styles['table_st']}>목적지IP</td>
                                <td className={styles['table_st']}>출발지포트</td>
                                <td className={styles['table_st']}>목적지 포트</td>
                                <td className={styles['table_st']}>접속 시간</td>
                        </tr>
                    {pcapHarmfulLog.map((domain, index) => (
                      
                            <tr>
                                <td className={styles['row_st']}>{domain.harmful_domain}</td> 
                                <td className={styles['row_st']}>{domain.src_ip}</td>
                                <td className={styles['row_st']}>{domain.des_ip} </td>
                                <td className={styles['row_st']}>{domain.src_port} </td>
                                <td className={styles['row_st']}>{domain.des_port}</td>
                                <td className={styles['row_st']}>{domain.created_at}</td>
                            </tr>

                    ))}
                    </table>
                ) : (
                    <p>No domains in the log.</p>
                )
            )}
            </div>
            
        </div>}
    </div>
  );
};

export default RightContent;
