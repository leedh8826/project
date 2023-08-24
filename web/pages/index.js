import { useState, useEffect } from 'react';

export async function getServerSideProps() {
    await new Promise(resolve => setTimeout(resolve, 3000));
    return { props: {} };
}

export default function Home({ initialHarmfulDomains }) {
    const [harmfulDomains, setHarmfulDomains] = useState(initialHarmfulDomains);
    const [domain, setDomain] = useState('');
    const [selectedDomains, setSelectedDomains] = useState([]);

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
    )
}