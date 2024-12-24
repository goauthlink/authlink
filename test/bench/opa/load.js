import http from 'k6/http';
import { check } from 'k6';

export const options = {
    vus: 10,
    duration: '30s',
};

export default function () {

    const reqJsonPath1 = {
        method: 'GET',
        url: 'http://localhost:8081/jwt_9/9',
        body: null,
        params: {
            headers: {
                'x-source': 'client1',
                'token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImNsaWVudDEiLCJpYXQiOjE1MTYyMzkwMjJ9.OiqoxQsfKfCLjGuud53bHbR3la7eO-iNW7MMeMqYZQs'
            },
        },
    };

    const reqJsonPath2 = {
        method: 'GET',
        url: 'http://localhost:8081/regex_8/1/sub_5/2',
        body: null,
        params: {
            headers: {
                'x-source': 'client2',
            },
        },
    };

    const reqJsonPath3 = {
        method: 'GET',
        url: 'http://localhost:8081/json_1/1',
        body: null,
        params: {
            headers: {
                'x-source': 'client2',
            },
        },
    };

    http.setResponseCallback(http.expectedStatuses(200, 403));

    const responses = http.batch([
        reqJsonPath1, reqJsonPath2, reqJsonPath3
    ]);

    check(responses[0], {
        'is status 403': (res) => (res.status === 403),
    });

    check(responses[1], {
        'is status 200': (res) => (res.status === 200),
    });

    check(responses[2], {
        'is status 200': (res) => (res.status === 200),
    });
}
