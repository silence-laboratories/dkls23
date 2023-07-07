import { test, expect } from 'vitest';

import { KeygenPartyKeys } from '../';

test('KeygenParyKeys', async () => {
    const keys = await KeygenPartyKeys.create();

    const bytes = keys.toBytes();

    const keys2 = KeygenPartyKeys.fromBytes(bytes);

    const bytes2 = keys2.toBytes();

    expect(bytes.toString()).to.equal(bytes2.toString());

})
