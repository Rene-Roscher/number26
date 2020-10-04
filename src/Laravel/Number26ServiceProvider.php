<?php


namespace RServices\Laravel;


use Illuminate\Support\ServiceProvider;

class Number26ServiceProvider extends ServiceProvider
{

    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        $this->app->bind('number26', function ($app) {
            return new \RServices\Number26(env('N26_MAIL'), env('N26_PASS'));
        });
    }

}
