﻿//Copyright (C) 2015  Timothy Watson, Jakub Pachansky

//This program is free software; you can redistribute it and/or
//modify it under the terms of the GNU General Public License
//as published by the Free Software Foundation; either version 2
//of the License, or (at your option) any later version.

//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.

//You should have received a copy of the GNU General Public License
//along with this program; if not, write to the Free Software
//Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

using System;
using System.Collections.Generic;
using System.Web.Http;
using ServiceConnect.Monitor.Interfaces;
using ServiceConnect.Monitor.Models;
using StructureMap;

namespace ServiceConnect.Monitor.Controllers
{
    public class HeartbeatController : ApiController
    {
        private readonly IHeartbeatRepository _heartbeatRepository;

        public HeartbeatController()
        {
            _heartbeatRepository = ObjectFactory.GetInstance<IHeartbeatRepository>();
        }

        [AcceptVerbs("GET")]
        [Route("heartbeats")]
        public List<Heartbeat> Find(string name, string location, DateTime from, DateTime to)
        {
            return _heartbeatRepository.Find(name, location, from, to);
        }
    }
}