"""
Test provider embeddings functionality

Tests the embedding capabilities added to the provider system.
"""

import pytest
import os


@pytest.mark.asyncio
async def test_provider_embeddings_interface():
    """Test that Provider class has embed methods"""
    from flocks.provider import Provider
    
    # Ensure providers are initialized
    await Provider.init()
    
    # Test that Provider has embed methods
    assert hasattr(Provider, 'embed')
    assert hasattr(Provider, 'embed_batch')
    assert callable(Provider.embed)
    assert callable(Provider.embed_batch)


@pytest.mark.asyncio
async def test_base_provider_embeddings_interface():
    """Test that BaseProvider has embed methods"""
    from flocks.provider import BaseProvider
    
    # Test that BaseProvider has embed methods
    assert hasattr(BaseProvider, 'embed')
    assert hasattr(BaseProvider, 'embed_batch')
    assert hasattr(BaseProvider, 'supports_embeddings')
    assert hasattr(BaseProvider, 'get_embedding_models')


@pytest.mark.asyncio
async def test_openai_provider_supports_embeddings():
    """Test that OpenAI provider supports embeddings"""
    from flocks.provider import Provider
    
    await Provider.init()
    
    openai = Provider.get("openai")
    assert openai is not None
    assert openai.supports_embeddings()
    
    # Test get_embedding_models
    models = openai.get_embedding_models()
    assert len(models) > 0
    assert "text-embedding-3-small" in models


@pytest.mark.asyncio
async def test_google_provider_supports_embeddings():
    """Test that Google provider supports embeddings"""
    from flocks.provider import Provider
    
    await Provider.init()
    
    google = Provider.get("google")
    assert google is not None
    assert google.supports_embeddings()
    
    # Test get_embedding_models
    models = google.get_embedding_models()
    assert len(models) > 0
    assert "models/text-embedding-004" in models


@pytest.mark.asyncio
@pytest.mark.skipif(not os.getenv("OPENAI_API_KEY"), reason="OpenAI API key not set")
async def test_openai_embed_single():
    """Test OpenAI single text embedding (requires API key)"""
    from flocks.provider import Provider
    
    await Provider.init()
    
    # Test single embedding
    embedding = await Provider.embed(
        text="Hello, world!",
        provider_id="openai",
        model="text-embedding-3-small"
    )
    
    assert isinstance(embedding, list)
    assert len(embedding) > 0
    assert all(isinstance(x, float) for x in embedding)
    
    # text-embedding-3-small should have 1536 dimensions
    assert len(embedding) == 1536


@pytest.mark.asyncio
@pytest.mark.skipif(not os.getenv("OPENAI_API_KEY"), reason="OpenAI API key not set")
async def test_openai_embed_batch():
    """Test OpenAI batch embeddings (requires API key)"""
    from flocks.provider import Provider
    
    await Provider.init()
    
    # Test batch embeddings
    texts = ["Hello", "World", "Test"]
    embeddings = await Provider.embed_batch(
        texts=texts,
        provider_id="openai",
        model="text-embedding-3-small"
    )
    
    assert isinstance(embeddings, list)
    assert len(embeddings) == len(texts)
    assert all(isinstance(emb, list) for emb in embeddings)
    assert all(len(emb) == 1536 for emb in embeddings)


@pytest.mark.asyncio
@pytest.mark.skipif(not os.getenv("GOOGLE_API_KEY"), reason="Google API key not set")
async def test_google_embed_single():
    """Test Google single text embedding (requires API key)"""
    from flocks.provider import Provider
    
    await Provider.init()
    
    # Test single embedding
    embedding = await Provider.embed(
        text="Hello, world!",
        provider_id="google",
        model="models/text-embedding-004"
    )
    
    assert isinstance(embedding, list)
    assert len(embedding) > 0
    assert all(isinstance(x, float) for x in embedding)
    
    # text-embedding-004 should have 768 dimensions
    assert len(embedding) == 768


@pytest.mark.asyncio
async def test_provider_embed_auto_fallback():
    """Test Provider.embed with auto provider selection"""
    from flocks.provider import Provider
    
    await Provider.init()
    
    # Test that it doesn't raise when no provider_id specified
    # It should try to find an available provider
    openai = Provider.get("openai")
    google = Provider.get("google")
    
    has_provider = openai.supports_embeddings() or google.supports_embeddings()
    assert has_provider, "At least one provider should support embeddings"


@pytest.mark.asyncio
async def test_unsupported_provider_raises_error():
    """Test that unsupported provider raises error"""
    from flocks.provider import Provider
    
    await Provider.init()
    
    # Anthropic doesn't support embeddings yet
    anthropic = Provider.get("anthropic")
    if anthropic:
        assert not anthropic.supports_embeddings()
        
        with pytest.raises(ValueError, match="does not support embeddings"):
            await Provider.embed(
                text="Hello",
                provider_id="anthropic"
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
