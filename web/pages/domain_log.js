import React, { useState, useEffect } from 'react';

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
            <h1>Domain Log</h1>
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
    );
};

export default DomainLogPage;
