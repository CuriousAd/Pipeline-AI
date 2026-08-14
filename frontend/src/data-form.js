import { useState } from 'react';
import {
    Box,
    Button,
    Chip,
    Paper,
    Stack,
    Typography,
} from '@mui/material';
import axios from 'axios';

const endpointMapping = {
    'Notion': 'notion',
    'Airtable': 'airtable',
    'HubSpot': 'hubspot',
};

export const DataForm = ({ integrationType, credentials }) => {
    const [loadedData, setLoadedData] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const endpoint = endpointMapping[integrationType];
    const summaryCounts = Array.isArray(loadedData)
        ? loadedData.reduce((counts, item) => {
            const type = item?.type || 'Unknown';
            counts[type] = (counts[type] || 0) + 1;
            return counts;
        }, {})
        : {};
    const previewItems = Array.isArray(loadedData) ? loadedData.slice(0, 8) : [];
    const formattedData = loadedData ? JSON.stringify(loadedData, null, 2) : '';

    const handleLoad = async () => {
        try {
            setIsLoading(true);
            const formData = new FormData();
            formData.append('credentials', JSON.stringify(credentials));
            const response = await axios.post(`http://localhost:8000/integrations/${endpoint}/load`, formData);
            const data = response.data;
            setLoadedData(data);
        } catch (e) {
            alert(e?.response?.data?.detail);
        } finally {
            setIsLoading(false);
        }
    }

    return (
        <Box display='flex' justifyContent='center' alignItems='center' flexDirection='column' width='100%'>
            <Box display='flex' flexDirection='column' width='100%' sx={{ gap: 2 }}>
                <Stack direction='row' spacing={2}>
                    <Button
                        onClick={handleLoad}
                        sx={{ mt: 2 }}
                        variant='contained'
                        disabled={isLoading}
                    >
                        {isLoading ? 'Loading...' : 'Load Data'}
                    </Button>
                    <Button
                        onClick={() => setLoadedData(null)}
                        sx={{ mt: 2 }}
                        variant='contained'
                    >
                        Clear Data
                    </Button>
                </Stack>

                {Array.isArray(loadedData) && (
                    <Paper variant='outlined' sx={{ p: 2, mt: 1 }}>
                        <Typography variant='subtitle1' sx={{ fontWeight: 600 }}>
                            Loaded Summary
                        </Typography>
                        <Stack direction='row' spacing={1} sx={{ mt: 1, flexWrap: 'wrap', gap: 1 }}>
                            <Chip label={`Total: ${loadedData.length}`} color='primary' />
                            {Object.entries(summaryCounts).map(([type, count]) => (
                                <Chip key={type} label={`${type}: ${count}`} variant='outlined' />
                            ))}
                        </Stack>
                        <Box sx={{ mt: 2, display: 'grid', gap: 1 }}>
                            {previewItems.length > 0 ? (
                                previewItems.map((item) => (
                                    <Paper
                                        key={item.id}
                                        variant='outlined'
                                        sx={{ p: 1.5, bgcolor: '#fafafa' }}
                                    >
                                        <Typography variant='body2' sx={{ fontWeight: 600 }}>
                                            {item.name || item.id}
                                        </Typography>
                                        <Typography variant='caption' color='text.secondary'>
                                            {item.type}
                                            {item.url ? ` • ${item.url}` : ''}
                                        </Typography>
                                    </Paper>
                                ))
                            ) : (
                                <Typography variant='body2' color='text.secondary'>
                                    No items were returned for this integration.
                                </Typography>
                            )}
                        </Box>
                    </Paper>
                )}

                <Paper variant='outlined' sx={{ p: 2 }}>
                    <Typography variant='subtitle1' sx={{ fontWeight: 600 }}>
                        Loaded Data
                    </Typography>
                    <Box
                        component='pre'
                        sx={{
                            mt: 1,
                            mb: 0,
                            p: 1.5,
                            bgcolor: '#111827',
                            color: '#f9fafb',
                            borderRadius: 1,
                            overflowX: 'auto',
                            maxHeight: 320,
                            fontSize: '0.8rem',
                        }}
                    >
                        {formattedData || 'No data loaded yet.'}
                    </Box>
                </Paper>
            </Box>
        </Box>
    );
}
