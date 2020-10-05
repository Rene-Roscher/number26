<?php

/**
 * @author   René Roscher <r.roscher@r-services.eu>
 */

namespace RServices;

use \Exception;
use Illuminate\Support\Arr;
use Ramsey\Uuid\Uuid;

class Number26
{

    protected $apiUrl = 'https://api.tech26.de';
    protected $accessToken = null;
    protected $refreshToken = null;
    protected $deviceToken = null;
    protected $expiresTime = 0;

    protected $apiResponse;
    protected $apiHeader;
    protected $apiInfo;
    protected $apiError;

    protected $username;
    protected $password;

    protected $store;
    protected $storeAccessTokensFile;

    protected $autoCollect;

    public function __construct($username, $password, $autoCollect = true)
    {
        $this->storeAccessTokensFile = storage_path('.n26');
        $this->checkDeviceToken();
        $this->autoCollect = $autoCollect;
        $this->username = $username;
        $this->password = $password;

        if ($this->isValidConnection())
            $this->loadProperties();
        else $this->login();
    }

    public function login()
    {
        $apiResult = $this->callApi('/oauth/token', [
            'grant_type' => 'password',
            'username' => $this->username,
            'password' => $this->password
        ], true, 'POST', true);

        if (Arr::exists($apiResult, 'error') && $apiResult['error'] == "mfa_required") {
            $this->requestMfaApproval($apiResult['mfaToken']);

            $apiResult = $this->completeAuthenticationFlow($apiResult['mfaToken']);

            throw_if(!$apiResult, new Exception("2FA request expired."));
        }

        if (Arr::exists($apiResult, 'error'))
            throw new Exception("{$apiResult['error']}: {$apiResult['detail']}");

        $this->setProperties($apiResult);
    }

    protected function checkDeviceToken()
    {
        if (!$this->deviceToken)
            if (!\Cache::has('device_token'))
                \Cache::forever('device_token', $this->deviceToken = Uuid::uuid4());
            else $this->deviceToken = \Cache::get('device_token');
    }

    protected function requestMfaApproval($mfaToken)
    {
        $this->callApi('/api/mfa/challenge', [
            'challengeType' => 'oob',
            'mfaToken' => $mfaToken
        ], $basic = true, 'POST', $json = true);
    }

    protected function completeAuthenticationFlow($mfaToken, $wait = 5, $max = 60)
    {
        $futureTime = time() + $max;
        while ($futureTime > time()) {
            $apiResult = $this->callApi('/oauth/token', [
                'grant_type' => 'mfa_oob',
                'mfaToken' => $mfaToken
            ], $basic = true, 'POST');
            if (Arr::exists($apiResult, 'access_token')) return $apiResult;

            sleep($wait);
        }
    }

    public function refreshSession($apiResource = null, $params = null, $basic = false, $method = null, $json = false)
    {
        $apiResult = $this->callApi('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $this->refreshToken
        ], true, 'POST', true);

        $description = Arr::exists($apiResult, 'error_description');
        if (Arr::exists($apiResult, 'error') || $description)
            if ($description && $apiResult['error_description'] == 'Refresh token not found!') {
                $this->login();
                if ($apiResource) $this->request($apiResource, $params, $basic, $method, $json);
            } else throw new Exception($apiResult['error'] . ': ' . $apiResult['error_description']);

        $this->setProperties($apiResult);

        if ($apiResource) $this->request($apiResource, $params, $basic, $method, $json);
    }

    protected function setProperties($apiResult)
    {
        file_put_contents($this->storeAccessTokensFile, json_encode([
            'expire' => $this->expiresTime = (time() + $apiResult['expires_in']),
            'token' => $this->accessToken = $apiResult['access_token'],
            'refresh' => $this->refreshToken = $apiResult['refresh_token']
        ]));
    }

    protected function loadProperties()
    {
        throw_if(!$tokens = json_decode(file_get_contents($this->storeAccessTokensFile), true),
            new \LogicException("Failed to load config from: {$this->storeAccessTokensFile}"));
        $this->accessToken = $tokens["token"];
        $this->refreshToken = $tokens["refresh"];
        $this->expiresTime = $tokens["expire"];
    }

    protected function isValidConnection()
    {
        return file_exists($this->storeAccessTokensFile);
    }

    protected function callApi($apiResource, $params = null, $basic = false, $method = 'GET', $json = false)
    {
        if ($basic == true && is_array($params) && count($params)) $apiResource = $apiResource . '?' . http_build_query($params);
        $this->request($apiResource, $params, $basic, $method, $json);
        return $this->apiResponse;
    }

    protected function request($apiResource, $params, $basic, $method, $json = false)
    {
        $response = \Http::withHeaders($this->getHeaders($basic, $json))->{$method}($this->apiUrl . $apiResource, $params);
        throw_if($response->status() == 429,
            new \LogicException('N26: Too many log-in attempts. Please try again in 30 minutes.'));
        $this->apiResponse = $response->json();
        $this->apiHeader = $response->headers();
        if (Arr::exists($this->apiResponse, 'error') && $this->apiResponse['error'] == 'invalid_token')
            $this->refreshSession($apiResource, $params, $basic, $method, $json);
    }

    protected function getHeaders($basic = false, $json = false)
    {
        $headers = [
            "Authorization" => ($basic ? 'Basic bXktdHJ1c3RlZC13ZHBDbGllbnQ6c2VjcmV0' : "Bearer $this->accessToken"),
            "Accept" => "*/*",
            "device-token" => strval($this->deviceToken),
        ];
        if ($json) $headers["Content-Type"] = "application/json";
        return $headers;
    }

    protected function buildParams(array $params = [])
    {
        return count($params) ? http_build_query($params) : '';
    }

    public function getMe($full = false)
    {
        $result = $this->callApi('/api/me' . ($full ? '?full=true' : ''));
        return $this->autoCollect ? collect($result) : $result;
    }

    public function getSpaces()
    {
        $callApi = $this->callApi('/api/spaces');
        return $this->autoCollect ? collect($callApi) : $callApi;
    }

    public function getCards()
    {
        $callApi = $this->callApi('/api/v2/cards');
        return $this->autoCollect ? collect($callApi) : $callApi;
    }

    public function getCard($id)
    {
        $callApi = $this->callApi('/api/cards/' . $id);
        return $this->autoCollect ? collect($callApi) : $callApi;
    }

    public function getAccounts()
    {
        $callApi = $this->callApi('/api/accounts');
        return $this->autoCollect ? collect($callApi) : $callApi;
    }

    public function getAddresses()
    {
        $callApi = $this->callApi('/api/addresses');
        return $this->autoCollect ? collect($callApi) : $callApi;
    }

    public function getAddress($id)
    {
        $callApi = $this->callApi('/api/addresses/' . $id);
        return $this->autoCollect ? collect($callApi) : $callApi;
    }

    public function getTransactions($params = [])
    {
        $transactions = $this->getSmrtTransactions($params);
        return $this->autoCollect ? collect($transactions) : $transactions;
    }

    public function getSmrtTransactions($params)
    {
        $params = (isset($params)) ? $this->buildParams($params) : '';
        return $this->callApi('/api/smrt/transactions' . $params);
    }

    public function getTransaction($id)
    {
        $callApi = $this->callApi('/api/transactions/' . $id);
        return $this->autoCollect ? collect($callApi) : $callApi;
    }

    public function getSmrtTransaction($id)
    {
        return $this->callApi('/api/smrt/transactions/' . $id);
    }

    public function getContacts()
    {
        $callApi = $this->callApi('/api/smrt/contacts');
        return $this->autoCollect ? collect($callApi) : $callApi;
    }

    public function getCategories()
    {
        $callApi = $this->callApi('/api/smrt/categories');
        return $this->autoCollect ? collect($callApi) : $callApi;
    }

    public function getFeaturesCountries($country)
    {
        $callApi = $this->callApi("/api/features/countries/$country");
        return $this->autoCollect ? collect($callApi) : $callApi;
    }

    public function makeTransfer($amount, $pin, $bic, $iban, $name, $reference)
    {
        return $this->callApi('/api/transactions', json_encode([
            'pin' => $pin,
            'transaction' => [
                'partnerBic' => $bic,
                'amount' => $amount,
                'type' => 'DT',
                'partnerIban' => $iban,
                'partnerName' => $name,
                'referenceText' => $reference
            ]
        ]), false, 'POST');
    }

}
