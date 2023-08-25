import { useState, useEffect } from 'react';
import styles from ".//style.module.css";
export default function Home({ initialHarmfulDomains }) {
    const [harmfulDomains, setHarmfulDomains] = useState(initialHarmfulDomains);
    const [domain, setDomain] = useState('');
    const [selectedDomains, setSelectedDomains] = useState([]);
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
    }

    function VerticalLine({ className }) {
        return <div className={`${styles['vertical-line']} ${className}`}></div>;
      }

    const handleAddDomain = async () => {
        try {
            const response = await fetch('/api/add-domain', {
                method: 'POST',
                headers: {
                'Content-Type': 'application/json',
                },
                body: JSON.stringify({ domain }),
            });
            if (response.ok) {
                if(response.status == 202) alert("중복 등록불가!");
                //console.log((await response.json()).message);
                //console.log('Domain added successfully.');
                // 추가 후에 원하는 동작 수행
                const updatedDomains = await fetchHarmfulDomains();
                setHarmfulDomains(updatedDomains);
            } else {
                console.error('Error adding domain.');
            }
        } catch (error) {
            console.error('Error adding domain:', error);
        }
    };

    const fetchHarmfulDomains = async () => {
        const response = await fetch('/api/get-harmful-domains');
        const data = await response.json();
        return data.harmfulDomains;
    };

    useEffect(() => {
        const fetchData = async () => {
            const updatedDomains = await fetchHarmfulDomains();
            setHarmfulDomains(updatedDomains);
        };
        fetchData();
    }, []);

    
    const handleCheckboxChange = (e, domain) => {
        if (e.target.checked) {
            setSelectedDomains(prevSelected => [...prevSelected, domain]);
        } else {
            setSelectedDomains(prevSelected => prevSelected.filter(d => d !== domain));
        }
    };

    const handleDeleteSelectedDomains = async () => {
        try {
            // 선택한 도메인들 삭제 처리 추가
            // 예: /api/delete-domains
            const response = await fetch('/api/delete-domains', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ domains: selectedDomains }),
            });

            if (response.ok) {
                console.log('Selected domains deleted successfully.');
                // 삭제 후에 원하는 동작 수행
                const updatedDomains = await fetchHarmfulDomains();
                setHarmfulDomains(updatedDomains);
                setSelectedDomains([]); // 선택 해제
            } else {
                console.error('Error deleting selected domains.');
            }
        } catch (error) {
            console.error('Error deleting selected domains:', error);
        }
    };
    if(1){
        return (

            <div>
            <div className={styles['main']}><a href='/'>메인 페이지</a></div>
            <div className={styles['log']}><a href='/domain_log'>접속 기록</a></div>
            <div className={styles['list']}>차단 도메인</div>
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
                        <tr>
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
        )
    }else{
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
        )
    }
}