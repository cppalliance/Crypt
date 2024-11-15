// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt


#ifndef BOOST_CRYPT_UTILITIES_ARRAY_HPP
#define BOOST_CRYPT_UTILITIES_ARRAY_HPP

#include <boost/crypt/utility/config.hpp>
#include <boost/crypt/utility/algorithm.hpp>
#include <boost/crypt/utility/cstdint.hpp>
#include <boost/crypt/utility/cstddef.hpp>
#include <boost/crypt/utility/type_traits.hpp>

#if !defined(BOOST_CRYPT_BUILD_MODULE) && !defined(BOOST_CRYPT_HAS_CUDA)
#include <array>
#endif

namespace boost {
namespace crypt {

template <typename T, boost::crypt::size_t N>
class array
{
public:

    class iterator {
    public:
        using value_type = T;
        using pointer = T*;
        using reference = T&;
        using difference_type = boost::crypt::ptrdiff_t;
        #ifndef BOOST_CRYPT_HAS_CUDA
        using iterator_category = std::random_access_iterator_tag;
        #else
        using iterator_category = cuda::std::random_access_iterator_tag;
        #endif

        BOOST_CRYPT_GPU_ENABLED constexpr iterator() noexcept : ptr_(nullptr) {}
        BOOST_CRYPT_GPU_ENABLED constexpr explicit iterator(pointer ptr) noexcept : ptr_(ptr) {}

        // Iterator operations
        BOOST_CRYPT_GPU_ENABLED constexpr auto operator*() noexcept -> reference { return *ptr_; }
        BOOST_CRYPT_GPU_ENABLED constexpr auto operator->() noexcept -> pointer { return ptr_; }
        BOOST_CRYPT_GPU_ENABLED constexpr auto operator[](difference_type n) noexcept -> reference { return ptr_[n]; }

        // Increment/Decrement
        BOOST_CRYPT_GPU_ENABLED constexpr auto operator++() noexcept -> iterator& { ++ptr_; return *this; }
        BOOST_CRYPT_GPU_ENABLED constexpr auto operator++(int) noexcept -> iterator { iterator tmp(*this); ++ptr_; return tmp; }
        BOOST_CRYPT_GPU_ENABLED constexpr auto operator--() noexcept -> iterator& { --ptr_; return *this; }
        BOOST_CRYPT_GPU_ENABLED constexpr auto operator--(int) noexcept -> iterator { iterator tmp(*this); --ptr_; return tmp; }

        // Arithmetic operations
        BOOST_CRYPT_GPU_ENABLED constexpr auto operator+=(difference_type n) noexcept -> iterator& { ptr_ += n; return *this; }
        BOOST_CRYPT_GPU_ENABLED constexpr auto operator-=(difference_type n) noexcept -> iterator& { ptr_ -= n; return *this; }

        // Comparison operators
        BOOST_CRYPT_GPU_ENABLED constexpr auto operator==(const iterator& other) const noexcept -> bool { return ptr_ == other.ptr_; }
        BOOST_CRYPT_GPU_ENABLED constexpr auto operator!=(const iterator& other) const noexcept -> bool { return ptr_ != other.ptr_; }
        BOOST_CRYPT_GPU_ENABLED constexpr auto operator<(const iterator& other) const noexcept -> bool { return ptr_ < other.ptr_; }
        BOOST_CRYPT_GPU_ENABLED constexpr auto operator>(const iterator& other) const noexcept -> bool { return ptr_ > other.ptr_; }
        BOOST_CRYPT_GPU_ENABLED constexpr auto operator<=(const iterator& other) const noexcept -> bool { return ptr_ <= other.ptr_; }
        BOOST_CRYPT_GPU_ENABLED constexpr auto operator>=(const iterator& other) const noexcept -> bool { return ptr_ >= other.ptr_; }

        BOOST_CRYPT_GPU_ENABLED friend constexpr auto operator+(iterator it, difference_type n) noexcept -> iterator { return it += n; }
        BOOST_CRYPT_GPU_ENABLED friend constexpr auto operator+(difference_type n, iterator it) noexcept -> iterator { return it += n; }
        BOOST_CRYPT_GPU_ENABLED friend constexpr auto operator-(iterator it, difference_type n) noexcept -> iterator { return it -= n; }
        BOOST_CRYPT_GPU_ENABLED friend constexpr auto operator-(const iterator& lhs, const iterator& rhs) noexcept -> difference_type
        { return lhs.operator->() - rhs.operator->(); }

    private:
        pointer ptr_;
    };

    class const_iterator {
    public:
        using value_type = const T;
        using pointer = const T*;
        using reference = const T&;
        using difference_type = boost::crypt::ptrdiff_t;
        #ifndef BOOST_CRYPT_HAS_CUDA
        using iterator_category = std::random_access_iterator_tag;
        #else
        using iterator_category = cuda::std::random_access_iterator_tag;
        #endif

        BOOST_CRYPT_GPU_ENABLED constexpr const_iterator() noexcept : ptr_(nullptr) {}
        BOOST_CRYPT_GPU_ENABLED constexpr explicit const_iterator(pointer ptr) noexcept : ptr_(ptr) {}

        // Iterator operations
        BOOST_CRYPT_GPU_ENABLED constexpr auto operator*() const noexcept -> reference { return *ptr_; }
        BOOST_CRYPT_GPU_ENABLED constexpr auto operator->() const noexcept -> pointer { return ptr_; }
        BOOST_CRYPT_GPU_ENABLED constexpr auto operator[](difference_type n) const noexcept -> reference { return ptr_[n]; }

        // Increment/Decrement
        BOOST_CRYPT_GPU_ENABLED constexpr auto operator++() noexcept -> const_iterator& { ++ptr_; return *this; }
        BOOST_CRYPT_GPU_ENABLED constexpr auto operator++(int) noexcept -> const_iterator { const_iterator tmp(*this); ++ptr_; return tmp; }
        BOOST_CRYPT_GPU_ENABLED constexpr auto operator--() noexcept -> const_iterator& { --ptr_; return *this; }
        BOOST_CRYPT_GPU_ENABLED constexpr auto operator--(int) noexcept -> const_iterator { const_iterator tmp(*this); --ptr_; return tmp; }

        // Arithmetic operations
        BOOST_CRYPT_GPU_ENABLED constexpr auto operator+=(difference_type n) noexcept -> const_iterator& { ptr_ += n; return *this; }
        BOOST_CRYPT_GPU_ENABLED constexpr auto operator-=(difference_type n) noexcept -> const_iterator& { ptr_ -= n; return *this; }

        // Comparison operators
        BOOST_CRYPT_GPU_ENABLED constexpr auto operator==(const const_iterator& other) const noexcept -> bool { return ptr_ == other.ptr_; }
        BOOST_CRYPT_GPU_ENABLED constexpr auto operator!=(const const_iterator& other) const noexcept -> bool { return ptr_ != other.ptr_; }
        BOOST_CRYPT_GPU_ENABLED constexpr auto operator<(const const_iterator& other) const noexcept -> bool { return ptr_ < other.ptr_; }
        BOOST_CRYPT_GPU_ENABLED constexpr auto operator>(const const_iterator& other) const noexcept -> bool { return ptr_ > other.ptr_; }
        BOOST_CRYPT_GPU_ENABLED constexpr auto operator<=(const const_iterator& other) const noexcept -> bool { return ptr_ <= other.ptr_; }
        BOOST_CRYPT_GPU_ENABLED constexpr auto operator>=(const const_iterator& other) const noexcept -> bool { return ptr_ >= other.ptr_; }

        BOOST_CRYPT_GPU_ENABLED friend constexpr auto operator+(const_iterator it, difference_type n) noexcept -> const_iterator { return it += n; }
        BOOST_CRYPT_GPU_ENABLED friend constexpr auto operator+(difference_type n, const_iterator it) noexcept -> const_iterator { return it += n; }
        BOOST_CRYPT_GPU_ENABLED friend constexpr auto operator-(const_iterator it, difference_type n) noexcept -> const_iterator { return it -= n; }
        BOOST_CRYPT_GPU_ENABLED friend constexpr auto operator-(const const_iterator& lhs, const const_iterator& rhs) noexcept -> difference_type
        { return lhs.operator->() - rhs.operator->(); }

    private:
        pointer ptr_;
    };

    using reference = T&;
    using const_reference = const T&;
    using size_type = boost::crypt::size_t;
    using difference_type = boost::crypt::ptrdiff_t;
    using value_type = T;
    using pointer = T*;
    using const_pointer = const T*;

    T elements[N];

    // Iterators
    BOOST_CRYPT_GPU_ENABLED constexpr auto begin() noexcept -> iterator { return iterator{elements}; }
    BOOST_CRYPT_GPU_ENABLED constexpr auto begin() const noexcept -> const_iterator { return const_iterator{elements}; }
    BOOST_CRYPT_GPU_ENABLED constexpr auto cbegin() const noexcept -> const_iterator { return const_iterator{elements}; }
    BOOST_CRYPT_GPU_ENABLED constexpr auto end() noexcept -> iterator { return iterator{elements + N}; }
    BOOST_CRYPT_GPU_ENABLED constexpr auto end() const noexcept -> const_iterator { return const_iterator{elements + N}; }
    BOOST_CRYPT_GPU_ENABLED constexpr auto cend() const noexcept -> const_iterator { return const_iterator{elements + N}; }

    // Sizing
    BOOST_CRYPT_GPU_ENABLED constexpr auto size() const noexcept -> size_type { return N; }
    BOOST_CRYPT_GPU_ENABLED constexpr auto max_size() const noexcept -> size_type { return N; }

    // Accessors
    BOOST_CRYPT_GPU_ENABLED constexpr auto operator[](size_type n) noexcept -> reference
    {
        BOOST_CRYPT_ASSERT(n < N);
        return elements[n];
    }

    BOOST_CRYPT_GPU_ENABLED constexpr auto operator[](size_type n) const noexcept -> const_reference
    {
        BOOST_CRYPT_ASSERT(n < N);
        return elements[n];
    }

    // For at instead of throwing on out of range return the last element since throwing doesn't work on device
    BOOST_CRYPT_GPU_ENABLED constexpr auto at(size_type n) noexcept -> reference
    {
        if (n >= N)
        {
            return elements[N - 1U];
        }
        return elements[n];
    }

    BOOST_CRYPT_GPU_ENABLED constexpr auto at(size_type n) const noexcept -> const_reference
    {
        if (n >= N)
        {
            return elements[N - 1U];
        }
        return elements[n];
    }

    // Front and back
    BOOST_CRYPT_GPU_ENABLED constexpr auto front() noexcept -> reference { return elements[0]; }
    BOOST_CRYPT_GPU_ENABLED constexpr auto front() const noexcept -> const_reference { return elements[0]; }
    BOOST_CRYPT_GPU_ENABLED constexpr auto back() noexcept -> reference { return elements[N - 1]; }
    BOOST_CRYPT_GPU_ENABLED constexpr auto back() const noexcept -> const_reference { return elements[N - 1]; }

    BOOST_CRYPT_GPU_ENABLED constexpr auto data() noexcept -> pointer { return elements; }
    BOOST_CRYPT_GPU_ENABLED constexpr auto data() const noexcept -> const_pointer { return elements; }

    // Fill and swap
    BOOST_CRYPT_GPU_ENABLED constexpr auto fill(const value_type& v) -> void
    {
        for (size_type i {}; i < N; ++i)
        {
            elements[i] = v;
        }
    }

    BOOST_CRYPT_GPU_ENABLED constexpr auto swap(array<value_type, N>& a)
    {
        const auto temp {a};
        a = *this;
        *this = temp;
    }

    #ifndef BOOST_CRYPT_HAS_CUDA
    constexpr operator std::array<T, N>() noexcept
    {
        std::array<T, N> new_array{};
        for (boost::crypt::size_t i {}; i < N; ++i)
        {
            new_array[i] = elements[i];
        }

        return new_array;
    }

    constexpr operator std::array<T, N>() const noexcept
    {
        std::array<T, N> new_array{};
        for (boost::crypt::size_t i {}; i < N; ++i)
        {
            new_array[i] = elements[i];
        }

        return new_array;
    }
    #endif
};

template <typename ForwardIter, typename T>
BOOST_CRYPT_GPU_ENABLED constexpr auto fill_array(ForwardIter first, ForwardIter last, T value)
{
    while (first != last)
    {
        *first++ = static_cast<decltype(*first)>(value);
    }
}

template<typename T, size_t N>
BOOST_CRYPT_GPU_ENABLED constexpr auto operator==(const array<T, N>& left, const array<T, N>& right) -> bool
{
    return boost::crypt::equal(left.begin(), left.end(), right.begin());
}

template<typename T, size_t N>
BOOST_CRYPT_GPU_ENABLED constexpr auto operator<(const array<T, N>& left, const array<T, N>& right) -> bool
{
    return boost::crypt::lexicographical_compare(left.begin(), left.end(), right.begin(), right.end());
}

template<typename T, size_t N>
BOOST_CRYPT_GPU_ENABLED constexpr auto operator!=(const array<T, N>& left, const array<T, N>& right) -> bool
{
    return (!(left == right));
}

template<typename T, size_t N>
BOOST_CRYPT_GPU_ENABLED constexpr auto operator>(const array<T, N>& left, const array<T, N>& right) -> bool
{
    return (right < left);
}

template<typename T, size_t N>
BOOST_CRYPT_GPU_ENABLED constexpr auto operator>=(const array<T, N>& left, const array<T, N>& right) -> bool
{
    return (!(left < right));
}

template<typename T, size_t N>
BOOST_CRYPT_GPU_ENABLED constexpr auto operator<=(const array<T, N>& left, const array<T, N>& right) -> bool
{
    return (!(right < left));
}

template<typename T>
class tuple_size;

template<typename T, typename boost::crypt::size_t N>
class tuple_size<boost::crypt::array<T, N>> : public boost::crypt::integral_constant<boost::crypt::size_t, N> { };

} // namespace crypt
} // namespace boost

namespace std {

template <typename T, boost::crypt::size_t N>
struct iterator_traits<boost::crypt::array<T, N>>
{
    using value_type = typename boost::crypt::array<T, N>::value_type;
    using pointer = typename boost::crypt::array<T, N>::pointer;
    using reference = typename boost::crypt::array<T, N>::reference;
    using difference_type = typename boost::crypt::array<T, N>::difference_type;
    #ifndef BOOST_CRYPT_HAS_CUDA
    using iterator_category = std::random_access_iterator_tag;
    #else
    using iterator_category = cuda::std::random_access_iterator_tag;
    #endif
};

} // namespace std

#endif // BOOST_CRYPT_UTILITIES_ARRAY_HPP
