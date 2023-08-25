import { useState, useEffect } from 'react';
import LeftMenu from './LeftMenu';
import RightContent from './RightContent';

const host = process.env.DB_HOST;
const user = process.env.DB_USER;
const password = process.env.DB_PASSWORD;
const database = process.env.DB_DATABASE;

console.log(`DB_HOST: ${host}`);
console.log(`DB_USER: ${user}`);
console.log(`DB_PASSWORD: ${password}`);
console.log(`DB_DATABASE: ${database}`);

export default function Home({ initialHarmfulDomains }) {
    const [harmfulDomains, setHarmfulDomains] = useState(initialHarmfulDomains);
    const [domain, setDomain] = useState('');
    const [selectedDomains, setSelectedDomains] = useState([]);
    const [selectedMenu, setSelectedMenu] = useState('menu1');

    
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
                />
            </div>
        </div>
    );
}