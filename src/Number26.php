<?php

/**
 * @author   René Roscher <r.roscher@r-services.eu>
 */

namespace RServices;

use \Exception;
use Illuminate\Support\Arr;
use Illuminate\Support\Collection;
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

    protected $store;
    protected $storeAccessTokensFile;

    protected $autoCollect;

    private $username, $password;

    public function __construct($username, $password, $autoCollect = true, $storeAccessTokensFile = '.n26', $storeConnection = true)
    {
        $this->password = $password;
        $this->username = $username;
        $this->storeAccessTokensFile = $storeAccessTokensFile;
        $this->checkDeviceToken();
        $this->autoCollect = $autoCollect;

        if ($storeConnection) {
            if (!$this->isValidConnection()) {
                $this->login();
            } else $this->loadProperties();
        } else $this->login();
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
            else
                $this->deviceToken = \Cache::get('device_token');
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
            if (Arr::exists($apiResult, 'access_token'))
                return $apiResult;

            sleep($wait);
        }
    }

    public function refreshSession($apiResource = null, $params = null, $basic = false, $method = null, $json = false)
    {
        $apiResult = $this->callApi('/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $this->refreshToken
        ], true, 'POST', true);

        if (Arr::exists($apiResult, 'error') || Arr::exists($apiResult, 'error_description')) {
            if ($apiResult['error'] == 'invalid_grant') {
                $this->login();
            } else throw new Exception($apiResult['error'] . ': ' . $apiResult['error_description']);
        } else $this->setProperties($apiResult);

        if ($apiResource) $this->request($apiResource, $params, $basic, $method, $json);
    }

    protected function setProperties($apiResult)
    {
        \Storage::put($this->storeAccessTokensFile, encrypt([
            'expire' => $this->expiresTime = time() + $apiResult['expires_in'],
            'token' => $this->accessToken = $apiResult['access_token'],
            'refresh' => $this->refreshToken = $apiResult['refresh_token']
        ]));
    }

    protected function loadProperties()
    {
        throw_if(!$tokens = decrypt(\Storage::get($this->storeAccessTokensFile), true),
            new \LogicException("Failed to load config from: {$this->storeAccessTokensFile}"));
        $this->accessToken = $tokens["token"];
        $this->refreshToken = $tokens["refresh"];
        $this->expiresTime = $tokens["expire"];
    }

    protected function isValidConnection()
    {
        return \Storage::exists($this->storeAccessTokensFile);
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
        return $this->autoCollect ? collect($result = $this->callApi('/api/me' . ($full ? '?full=true' : ''))) : $result;
    }

    public function getSpaces()
    {
        return $this->callApi('/api/spaces');
    }

    public function getCards()
    {
        return $this->callApi('/api/v2/cards');
    }

    public function getCard($id)
    {
        return $this->callApi('/api/cards/' . $id);
    }

    public function getAccounts()
    {
        return $this->callApi('/api/accounts');
    }

    public function getAddresses()
    {
        return $this->callApi('/api/addresses');
    }

    public function getAddress($id)
    {
        return $this->callApi('/api/addresses/' . $id);
    }

    public function getTransactions($params = [])
    {
        return $this->getSmrtTransactions($params);
    }

    public function getSmrtTransactions($params)
    {
        $params = (isset($params)) ? $this->buildParams($params) : '';
        return $this->callApi('/api/smrt/transactions' . $params);
    }

    public function getTransaction($id)
    {
        return $this->callApi('/api/transactions/' . $id);
    }

    public function getSmrtTransaction($id)
    {
        return $this->callApi('/api/smrt/transactions/' . $id);
    }

    public function getRecipients()
    {
        return $this->callApi('/api/transactions/recipients');
    }

    public function getContacts()
    {
        return $this->callApi('/api/smrt/contacts');
    }

    public function getCategories()
    {
        return $this->callApi('/api/smrt/categories');
    }

    public function getFeaturesCountries($country)
    {
        return $this->callApi("/api/features/countries/$country");
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
