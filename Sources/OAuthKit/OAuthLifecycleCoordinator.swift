import Foundation

struct OAuthLifecycleTicket: Equatable, Sendable {
    let namespaceGeneration: UInt64
    let providerGeneration: UInt64
    let instanceGeneration: UInt64
    let instanceProviderGeneration: UInt64
}

enum OAuthRefreshOutcome: Sendable {
    case success
    case failure(OAError)
    case unchanged
    case cleared
    case cancelled
}

@MainActor
protocol OAuthLifecycleParticipant: AnyObject {
    func lifecycleDidInvalidate(providerID: String?)
    func lifecycleCredentialsDidClear()
}

@MainActor
final class OAuthLifecycleCoordinator {
    private final class WeakCoordinatorReference {
        weak var value: OAuthLifecycleCoordinator?

        init(_ value: OAuthLifecycleCoordinator) {
            self.value = value
        }
    }

    private final class WeakParticipantReference {
        weak var value: (any OAuthLifecycleParticipant)?

        init(_ value: any OAuthLifecycleParticipant) {
            self.value = value
        }
    }

    private struct TaskEntry {
        let providerID: String
        let ownerID: ObjectIdentifier
        let task: Task<Void, Never>
    }

    struct RefreshFlight {
        let id: UUID
        let ownerID: ObjectIdentifier
        let task: Task<OAuthRefreshOutcome, Never>
        var waiterCount: Int
    }

    private static var coordinators = [String: WeakCoordinatorReference]()

    static func coordinator(for namespace: String) -> OAuthLifecycleCoordinator {
        coordinators = coordinators.filter { $0.value.value != nil }
        if let existing = coordinators[namespace]?.value {
            return existing
        }
        let coordinator = OAuthLifecycleCoordinator()
        coordinators[namespace] = WeakCoordinatorReference(coordinator)
        return coordinator
    }

    private var namespaceGeneration: UInt64 = 0
    private var providerGenerations = [String: UInt64]()
    private var tasks = [UUID: TaskEntry]()
    private var refreshFlights = [String: RefreshFlight]()
    private var participants = [ObjectIdentifier: WeakParticipantReference]()

    private init() {}

    func register(_ participant: any OAuthLifecycleParticipant) {
        let id = ObjectIdentifier(participant)
        participants[id] = WeakParticipantReference(participant)
    }

    func unregister(_ participant: any OAuthLifecycleParticipant) {
        participants.removeValue(forKey: ObjectIdentifier(participant))
    }

    func ticket(
        for providerID: String,
        instanceGeneration: UInt64,
        instanceProviderGeneration: UInt64
    ) -> OAuthLifecycleTicket {
        OAuthLifecycleTicket(
            namespaceGeneration: namespaceGeneration,
            providerGeneration: providerGenerations[providerID, default: 0],
            instanceGeneration: instanceGeneration,
            instanceProviderGeneration: instanceProviderGeneration
        )
    }

    func isCurrent(
        _ ticket: OAuthLifecycleTicket,
        for providerID: String,
        instanceGeneration: UInt64,
        instanceProviderGeneration: UInt64
    ) -> Bool {
        ticket.namespaceGeneration == namespaceGeneration &&
            ticket.providerGeneration == providerGenerations[providerID, default: 0] &&
            ticket.instanceGeneration == instanceGeneration &&
            ticket.instanceProviderGeneration == instanceProviderGeneration
    }

    func invalidate(providerID: String?, excluding participantID: ObjectIdentifier? = nil) {
        if let providerID {
            providerGenerations[providerID, default: 0] &+= 1
            let matchingTasks = tasks.filter { $0.value.providerID == providerID }
            for (id, entry) in matchingTasks {
                entry.task.cancel()
                tasks.removeValue(forKey: id)
            }
            if let flight = refreshFlights.removeValue(forKey: providerID) {
                flight.task.cancel()
            }
        } else {
            namespaceGeneration &+= 1
            for entry in tasks.values { entry.task.cancel() }
            tasks.removeAll()
            for flight in refreshFlights.values { flight.task.cancel() }
            refreshFlights.removeAll()
            providerGenerations.removeAll()
        }
        notifyParticipants(providerID: providerID, excluding: participantID)
    }
    func credentialsDidClear(excluding participantID: ObjectIdentifier? = nil) {
        participants = participants.filter { $0.value.value != nil }
        for (id, reference) in participants where id != participantID {
            reference.value?.lifecycleCredentialsDidClear()
        }
    }

    func invalidateOwnedWork(ownerID: ObjectIdentifier) {
        let ownedTasks = tasks.filter { $0.value.ownerID == ownerID }
        for (id, entry) in ownedTasks {
            entry.task.cancel()
            tasks.removeValue(forKey: id)
        }
        let ownedFlights = refreshFlights.filter { $0.value.ownerID == ownerID }
        for (providerID, flight) in ownedFlights {
            flight.task.cancel()
            refreshFlights.removeValue(forKey: providerID)
        }
    }

    func retain(_ task: Task<Void, Never>, id: UUID, providerID: String, ownerID: ObjectIdentifier) {
        tasks[id] = TaskEntry(providerID: providerID, ownerID: ownerID, task: task)
    }

    func finishedTask(id: UUID) {
        tasks.removeValue(forKey: id)
    }

    func refreshFlight(for providerID: String) -> RefreshFlight? {
        refreshFlights[providerID]
    }

    func joinRefreshFlight(for providerID: String) -> RefreshFlight? {
        guard var flight = refreshFlights[providerID] else { return nil }
        flight.waiterCount += 1
        refreshFlights[providerID] = flight
        return flight
    }
    func retainRefresh(
        _ task: Task<OAuthRefreshOutcome, Never>,
        id: UUID,
        providerID: String,
        ownerID: ObjectIdentifier
    ) {
        refreshFlights[providerID] = RefreshFlight(id: id, ownerID: ownerID, task: task, waiterCount: 1)
    }

    func finishRefresh(id: UUID, providerID: String) {
        guard refreshFlights[providerID]?.id == id else { return }
        refreshFlights.removeValue(forKey: providerID)
    }

    private func notifyParticipants(providerID: String?, excluding participantID: ObjectIdentifier?) {
        participants = participants.filter { $0.value.value != nil }
        for (id, reference) in participants where id != participantID {
            reference.value?.lifecycleDidInvalidate(providerID: providerID)
        }
    }
}
