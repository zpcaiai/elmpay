# WeChat Pay connector

`WechatPayAdapter` implements the public APIv3 RSA request format, bounded HTTP execution, JSAPI/mini-program/Native/H5/App actions, query, close, refund, bill digest verification, and RSA-before-AES-GCM callback verification. Platform public keys support overlap rotation and callbacks are bound to merchant, app, order, transaction, integer amount, and currency.

Credentials are supplied at runtime; none are stored here. Official merchant onboarding, product activation, callbacks, bills, client/device runs, and sandbox certification remain `NOT_RUN`.
