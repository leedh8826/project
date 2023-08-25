import React, { useState, useEffect } from 'react';
import LeftMenu from './LeftMenu';
import RightContent from './RightContent';

export default function Home({ initialHarmfulDomains }) {
    const [harmfulDomains, setHarmfulDomains] = useState(initialHarmfulDomains);
    const [domain, setDomain] = useState('');
    const [selectedDomains, setSelectedDomains] = useState([]);
    const [selectedMenu, setSelectedMenu] = useState('menu1');
    const [pcapHarmfulLog, setPcapHarmfulLog] = useState([]);
    const [isLoading, setIsLoading] = useState(true);

    const handleMenuSelect = (menu) => {
        setSelectedMenu(menu);
    };

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
            try {
                const updatedDomains = await fetchHarmfulDomains();
                setHarmfulDomains(updatedDomains);
                const response = await fetch('/api/get-domains-log');
                const data = await response.json();
                setPcapHarmfulLog(data.pcapHarmfulLog);
                setIsLoading(false); // 데이터 로딩 완료
            } catch (error) {
                console.error('Error fetching domain list:', error);
                setIsLoading(false); // 데이터 로딩 실패
            }
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

    return (
        <div className="container">
            <div className="left-container">
                <LeftMenu onSelect={handleMenuSelect} />
            </div>
            <div className="right-container">
                <RightContent
                selectedMenu={selectedMenu}
                harmfulDomains={harmfulDomains}
                selectedDomains={selectedDomains}
                handleCheckboxChange={handleCheckboxChange}
                handleAddDomain={handleAddDomain}
                handleDeleteSelectedDomains={handleDeleteSelectedDomains}
                domain={domain}
                setDomain={setDomain}
                pcapHarmfulLog={pcapHarmfulLog}
                isLoading={isLoading}
                />
            </div>
        </div>
    );
}