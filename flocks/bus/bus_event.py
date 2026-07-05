"""
Bus Event Definition

Defines event types for the event bus system.
Based on Flocks' ported src/bus/bus-event.ts
"""

from typing import TypeVar, Generic, Dict, Type, Any
from pydantic import BaseModel
from flocks.utils.log import Log


log = Log.create(service="event")


class EventDefinition(Generic[TypeVar("T")]):
    """
    Event definition with type and schema
    
    Matches TypeScript BusEvent.Definition
    """
    
    def __init__(self, event_type: str, properties_schema: Type[BaseModel]):
        """
        Initialize event definition
        
        Args:
            event_type: Unique event type identifier (e.g., "session.created")
            properties_schema: Pydantic model for event properties validation
        """
        self.type = event_type
        self.properties_schema = properties_schema
    
    def validate(self, properties: Dict[str, Any]) -> BaseModel:
        """
        Validate event properties against schema
        
        Args:
            properties: Event properties to validate
            
        Returns:
            Validated properties instance
        """
        return self.properties_schema(**properties)


class BusEvent:
    """
    Event definition registry
    
    Mirrors original Flocks BusEvent namespace from bus-event.ts
    """
    
    _registry: Dict[str, EventDefinition] = {}
    
    @classmethod
    def define(
        cls,
        event_type: str,
        properties_schema: Type[BaseModel],
    ) -> EventDefinition:
        """
        Define a new event type
        
        Matches TypeScript BusEvent.define()
        
        Args:
            event_type: Unique event type identifier
            properties_schema: Pydantic model for properties
            
        Returns:
            Event definition
            
        Example:
            >>> class SessionCreatedProps(BaseModel):
            ...     session_id: str
            ...     project_id: str
            >>> 
            >>> SessionCreated = BusEvent.define(
            ...     "session.created",
            ...     SessionCreatedProps
            ... )
        """
        definition = EventDefinition(event_type, properties_schema)
        cls._registry[event_type] = definition
        
        log.debug("event.defined", {"type": event_type})
        
        return definition
    
    @classmethod
    def get_definition(cls, event_type: str) -> EventDefinition:
        """
        Get event definition by type
        
        Args:
            event_type: Event type
            
        Returns:
            Event definition
            
        Raises:
            KeyError: If event type not registered
        """
        if event_type not in cls._registry:
            raise KeyError(f"Event type '{event_type}' not registered")
        return cls._registry[event_type]
    
    @classmethod
    def list_types(cls) -> list[str]:
        """
        List all registered event types
        
        Returns:
            List of event type strings
        """
        return list(cls._registry.keys())
    
    @classmethod
    def clear_registry(cls) -> None:
        """Clear event registry (for testing)"""
        cls._registry.clear()
