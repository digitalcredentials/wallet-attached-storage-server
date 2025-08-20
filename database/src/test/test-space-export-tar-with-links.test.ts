import { describe, test } from 'node:test'
import assert from 'assert'
import { createDatabaseFromSqlite3Url } from '../sqlite3/database-url-sqlite3.ts'
import { initializeDatabaseSchema } from '../schema.ts'
import SpaceRepository from '../space-repository.ts'
import ResourceRepository from '../resource-repository.ts'
import type { Database, ISpace } from '../types.ts'
import { collect } from 'streaming-iterables'

await test(`iterateSpaceRepresentationsWithLinks yields files with credential id filenames`, async t => {
  // setup db
  let database: Database
  {
    database = createDatabaseFromSqlite3Url(`sqlite3::memory:`)
    await initializeDatabaseSchema(database)
  }

  // create a space
  let createdSpace: ISpace
  {
    const spaceToCreate = {
      name: 'test-space',
      uuid: crypto.randomUUID(),
      controller: null,
      link: null,
    }
    await new SpaceRepository(database).create(spaceToCreate)
    createdSpace = spaceToCreate
  }

  // add a resource to the space
  const resourceBlob = new Blob(['hello world'], { type: 'application/json' })
  {
    await new ResourceRepository(database).putSpaceNamedResource({
      space: createdSpace.uuid,
      name: 'test-resource',
      representation: resourceBlob,
    })
  }

  // iterate using the new function
  const repo = new ResourceRepository(database)
  const results = await collect(
    repo.iterateSpaceRepresentationsWithLinks({ space: createdSpace.uuid })
  )

  // assertions
  assert.equal(results.length, 1, 'should yield one resource')
  const file = results[0].blob
  assert.ok(file instanceof File, 'yielded value should be a File')
  assert.match(file.name, /\.json$/, 'filename should end with .json')
  assert.equal(file.type, 'application/json', 'file type should be preserved')
})
