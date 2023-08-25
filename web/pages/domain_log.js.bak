import React, { useState, useEffect } from 'react';
import styles from ".//style.module.css";
function VerticalLine({ className }) {
    return <div className={`${styles['vertical-line']} ${className}`}></div>;
  }
const DomainLogPage = () => {
    const [pcapHarmfulLog, setPcapHarmfulLog] = useState([]);
    const [isLoading, setIsLoading] = useState(true);

    useEffect(() => {
        const fetchData = async () => {
        try {
          const response = await fetch('/api/get-domains-log');
          const data = await response.json();
          setPcapHarmfulLog(data.pcapHarmfulLog);
          setIsLoading(false); // 데이터 로딩 완료
        } catch (error) {
          console.error('Error fetching domain list:', error);
          setIsLoading(false); // 데이터 로딩 실패
        }
        };

        fetchData(); // fetchData 함수 호출
    }, []);

    return (

        <div>
            <div className={styles['main']}><a href='/'>메인 페이지</a></div>
            <div className={styles['log']}><a href='/domain_log'>접속 기록</a></div>
            <div className={styles['list']}>차단 도메인</div>
            <h2> Solution Development Phase1 </h2>
            <hr></hr>
            <VerticalLine className={styles['vertical-line']} />

            {isLoading ? (
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
        </div>
    );
};

export default DomainLogPage;
