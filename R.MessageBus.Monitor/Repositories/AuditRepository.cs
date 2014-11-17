﻿using MongoDB.Driver;
using MongoDB.Driver.Builders;
using R.MessageBus.Monitor.Interfaces;
using R.MessageBus.Monitor.Models;

namespace R.MessageBus.Monitor.Repositories
{
    public class AuditRepository : IAuditRepository
    {
        private readonly MongoCollection<Audit> _auditCollection;
        private readonly MongoCollection<Service> _serviceCollection;
        private readonly MongoCollection<ServiceMessage> _serviceMessagesCollection;

        public AuditRepository(string mongoConnectionString)
        {
            var mongoClient = new MongoClient(mongoConnectionString);
            MongoServer server = mongoClient.GetServer();
            var mongoDatabase = server.GetDatabase("RMessageBusMonitor");
            _auditCollection = mongoDatabase.GetCollection<Audit>("Audit");
            _serviceCollection = mongoDatabase.GetCollection<Service>("Services");
            _serviceMessagesCollection = mongoDatabase.GetCollection<ServiceMessage>("ServiceMessages");
        }

        public void InsertAudit(Audit model)
        {
            _auditCollection.Insert(model);

            _serviceCollection.Update(
                Query<Service>.EQ(x => x.Name, model.SourceAddress),
                Update<Service>.AddToSet(x => x.InstanceLocation, model.SourceMachine).
                                AddToSet(x => x.Out, model.TypeName),
                UpdateFlags.Upsert);

            _serviceCollection.Update(
                Query<Service>.EQ(x => x.Name, model.DestinationAddress),
                Update<Service>.AddToSet(x => x.InstanceLocation, model.DestinationMachine).
                                AddToSet(x => x.In, model.TypeName),
                UpdateFlags.Upsert);

            _serviceMessagesCollection.Update(
                Query.And(
                    Query<ServiceMessage>.EQ(x => x.In, model.DestinationAddress),
                    Query<ServiceMessage>.EQ(x => x.Out, model.SourceAddress)
                ),
                Update<ServiceMessage>.Inc(x => x.Count, 1).
                                       Set(x => x.LastSent, model.TimeReceived).
                                       Set(x => x.Type, model.TypeName),
                UpdateFlags.Upsert);
        }
    }
}